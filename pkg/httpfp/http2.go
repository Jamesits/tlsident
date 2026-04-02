package httpfp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"tlsident/pkg/api"
	"tlsident/pkg/capture"
)

const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

type HTTP2Handler struct {
	handler api.Handler
	logger  *slog.Logger
}

func NewHTTP2Handler(handler api.Handler, logger *slog.Logger) *HTTP2Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &HTTP2Handler{handler: handler, logger: logger}
}

func (h *HTTP2Handler) Serve(conn *tls.Conn, connection capture.ConnectionInfo, tlsInfo capture.TLSInfo) error {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	framer := http2.NewFramer(writer, reader)
	framer.ReadMetaHeaders = nil

	preface := make([]byte, len(clientPreface))
	if _, err := io.ReadFull(reader, preface); err != nil {
		return err
	}
	if string(preface) != clientPreface {
		return fmt.Errorf("invalid http/2 preface")
	}

	if err := framer.WriteSettings(); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	tracker := &HTTP2Tracker{}
	var emitted []HeaderField
	decoder := hpack.NewDecoder(4096, func(field hpack.HeaderField) {
		emitted = append(emitted, HeaderField{Name: field.Name, Value: field.Value})
	})

	requests := map[uint32]*requestState{}

	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			return err
		}

		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if frame.IsAck() {
				continue
			}
			if err := tracker.RecordSettings(frame); err != nil {
				return err
			}
			if err := framer.WriteSettingsAck(); err != nil {
				return err
			}
			if err := writer.Flush(); err != nil {
				return err
			}
		case *http2.WindowUpdateFrame:
			if frame.StreamID == 0 {
				tracker.RecordWindowUpdate(frame.Increment)
			}
		case *http2.PriorityFrame:
			tracker.RecordPriority(PriorityFrame{StreamID: frame.Header().StreamID, PriorityParam: frame.PriorityParam})
		case *http2.HeadersFrame:
			block, err := readHeaderBlock(framer, frame)
			if err != nil {
				return err
			}
			emitted = emitted[:0]
			if _, err := decoder.Write(block); err != nil {
				return err
			}

			request := requests[frame.Header().StreamID]
			if request == nil {
				request = &requestState{}
				requests[frame.Header().StreamID] = request
			}
			request.addHeaders(emitted)
			tracker.RecordPseudoHeaderOrder(emitted)
			if frame.StreamEnded() {
				if err := h.respondHTTP2Request(framer, writer, frame.Header().StreamID, connection, tlsInfo, tracker.Snapshot(), request); err != nil {
					return err
				}
				delete(requests, frame.Header().StreamID)
			}
		case *http2.DataFrame:
			request := requests[frame.Header().StreamID]
			if request == nil {
				request = &requestState{}
				requests[frame.Header().StreamID] = request
			}
			request.body.Write(frame.Data())
			if frame.StreamEnded() {
				if err := h.respondHTTP2Request(framer, writer, frame.Header().StreamID, connection, tlsInfo, tracker.Snapshot(), request); err != nil {
					return err
				}
				delete(requests, frame.Header().StreamID)
			}
		case *http2.PingFrame:
			if !frame.Flags.Has(http2.FlagPingAck) {
				if err := framer.WritePing(true, frame.Data); err != nil {
					return err
				}
				if err := writer.Flush(); err != nil {
					return err
				}
			}
		case *http2.GoAwayFrame:
			return nil
		case *http2.RSTStreamFrame:
			delete(requests, frame.Header().StreamID)
		}
	}
}

type requestState struct {
	headers map[string][]string
	method  string
	path    string
	body    bytes.Buffer
}

func (r *requestState) addHeaders(fields []HeaderField) {
	if r.headers == nil {
		r.headers = make(map[string][]string)
	}
	for _, field := range fields {
		if strings.HasPrefix(field.Name, ":") {
			switch field.Name {
			case ":method":
				r.method = field.Value
			case ":path":
				r.path = field.Value
			}
			continue
		}
		r.headers[strings.ToLower(field.Name)] = append(r.headers[strings.ToLower(field.Name)], field.Value)
	}
}

func readHeaderBlock(framer *http2.Framer, first *http2.HeadersFrame) ([]byte, error) {
	var block bytes.Buffer
	block.Write(first.HeaderBlockFragment())
	if first.HeadersEnded() {
		return block.Bytes(), nil
	}
	streamID := first.Header().StreamID
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return nil, err
		}
		continuation, ok := frame.(*http2.ContinuationFrame)
		if !ok || continuation.Header().StreamID != streamID {
			return nil, fmt.Errorf("expected continuation frame")
		}
		block.Write(continuation.HeaderBlockFragment())
		if continuation.HeadersEnded() {
			return block.Bytes(), nil
		}
	}
}

func (h *HTTP2Handler) respondHTTP2Request(framer *http2.Framer, writer *bufio.Writer, streamID uint32, connection capture.ConnectionInfo, tlsInfo capture.TLSInfo, http2Info capture.HTTP2Info, request *requestState) error {
	path := stripQuery(request.path)
	headers := normalizeHeaderMap(request.headers)
	response := h.handler.Handle(api.RequestContext{
		Connection: connection,
		TLS:        tlsInfo,
		HTTP2:      http2Info,
		Method:     request.method,
		Path:       path,
		Headers:    headers,
		Body:       request.body.Bytes(),
	})
	h.logger.Info("http request",
		"protocol", "h2",
		"client_ip", connection.ClientIP,
		"method", request.method,
		"path", path,
		"status", response.StatusCode,
		"user_agent", firstHeaderValue(headers, "user-agent"),
	)

	headerBlock, err := encodeResponseHeaders(response, len(response.Body))
	if err != nil {
		return err
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: headerBlock,
		EndHeaders:    true,
		EndStream:     len(response.Body) == 0,
	}); err != nil {
		return err
	}
	if len(response.Body) > 0 {
		if err := framer.WriteData(streamID, true, response.Body); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func encodeResponseHeaders(response api.Response, contentLength int) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := hpack.NewEncoder(&buffer)
	fields := []HeaderField{{Name: ":status", Value: strconv.Itoa(response.StatusCode)}}
	for key, value := range response.Headers {
		fields = append(fields, HeaderField{Name: strings.ToLower(key), Value: value})
	}
	if contentLength >= 0 {
		fields = append(fields, HeaderField{Name: "content-length", Value: strconv.Itoa(contentLength)})
	}
	for _, field := range fields {
		if err := encoder.WriteField(hpack.HeaderField{Name: field.Name, Value: field.Value}); err != nil {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}

func stripQuery(path string) string {
	if index := strings.IndexByte(path, '?'); index >= 0 {
		return path[:index]
	}
	return path
}
