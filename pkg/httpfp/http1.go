package httpfp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/textproto"
	"sort"
	"strings"
	"time"

	"tlsident/pkg/api"
	"tlsident/pkg/capture"
	"tlsident/pkg/tlsfp"
)

type HTTP1Handler struct {
	handler api.Handler
	logger  *slog.Logger
}

func NewHTTP1Handler(handler api.Handler, logger *slog.Logger) *HTTP1Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &HTTP1Handler{handler: handler, logger: logger}
}

func (h *HTTP1Handler) Serve(conn *tls.Conn, connection capture.ConnectionInfo, clientHello *tlsfp.ClientHello, tlsInfo capture.TLSInfo, clientPort int) error {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		request, err := http.ReadRequest(reader)
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			return err
		}

		body, err := io.ReadAll(request.Body)
		_ = request.Body.Close()
		if err != nil {
			return err
		}

		response := h.handler.Handle(api.RequestContext{
			Connection:  connection,
			ClientHello: clientHello,
			TLS:         tlsInfo,
			HTTP2:       capture.HTTP2Info{Fingerprint: "|00|0|"},
			Protocol:    "HTTP/1.1",
			Host:        request.Host,
			ClientPort:  clientPort,
			HTTP1: api.HTTP1RequestInfo{
				HeaderLines: http1HeaderLines(request),
			},
			Method:  request.Method,
			Path:    request.URL.Path,
			Headers: normalizeHeaderMap(request.Header),
			Body:    body,
		})
		h.logger.Info("http request",
			"protocol", "http/1.1",
			"client_ip", connection.ClientIP,
			"method", request.Method,
			"path", request.URL.Path,
			"status", response.StatusCode,
			"user_agent", request.UserAgent(),
		)

		httpResponse := &http.Response{
			StatusCode:    response.StatusCode,
			Status:        fmt.Sprintf("%d %s", response.StatusCode, http.StatusText(response.StatusCode)),
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          io.NopCloser(bytes.NewReader(response.Body)),
			ContentLength: int64(len(response.Body)),
			Close:         request.Close,
		}
		for key, value := range response.Headers {
			httpResponse.Header.Set(key, value)
		}
		if httpResponse.Header.Get("Date") == "" {
			httpResponse.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
		}

		if err := httpResponse.Write(writer); err != nil {
			return err
		}
		if err := writer.Flush(); err != nil {
			return err
		}

		if request.Close {
			return nil
		}
	}
}

func http1HeaderLines(request *http.Request) []string {
	lines := make([]string, 0, len(request.Header)+1)
	if request.Host != "" {
		lines = append(lines, "Host: "+request.Host)
	}

	keys := make([]string, 0, len(request.Header))
	for key := range request.Header {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		canonical := textproto.CanonicalMIMEHeaderKey(key)
		for _, value := range request.Header[key] {
			lines = append(lines, canonical+": "+value)
		}
	}

	return lines
}
