package httpfp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"tlsident/pkg/api"
	"tlsident/pkg/capture"
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

func (h *HTTP1Handler) Serve(conn *tls.Conn, connection capture.ConnectionInfo, tlsInfo capture.TLSInfo) error {
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
			Connection: connection,
			TLS:        tlsInfo,
			HTTP2:      capture.HTTP2Info{Fingerprint: "|00|0|", AkamaiFingerprint: "|00|0|"},
			Method:     request.Method,
			Path:       request.URL.Path,
			Headers:    normalizeHeaderMap(request.Header),
			Body:       body,
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
