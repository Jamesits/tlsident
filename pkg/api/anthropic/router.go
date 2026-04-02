package anthropic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"tlsident/pkg/api"
	"tlsident/pkg/capture"
	"tlsident/pkg/version"
)

type Service struct {
	store  *capture.Store
	logger *slog.Logger
}

func NewService(store *capture.Store, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{store: store, logger: logger}
}

func (s *Service) Handle(ctx api.RequestContext) api.Response {
	switch {
	case ctx.Method == "GET" && ctx.Path == "/captures":
		return jsonResponse(200, s.store.Snapshot())
	case ctx.Method == "POST" && ctx.Path == "/reset":
		s.store.Reset()
		return jsonResponse(200, map[string]bool{"ok": true})
	case ctx.Method == "POST" && ctx.Path == "/v1/messages/count_tokens":
		return jsonResponse(200, s.countTokens(ctx.Body))
	case ctx.Method == "POST" && ctx.Path == "/v1/messages":
		return s.handleMessages(ctx)
	default:
		return jsonResponse(404, map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "not_found_error",
				"message": fmt.Sprintf("unsupported endpoint %s %s", ctx.Method, ctx.Path),
			},
		})
	}
}

func (s *Service) handleMessages(ctx api.RequestContext) api.Response {
	payload := parseJSON(ctx.Body)
	model, _ := payload["model"].(string)
	stream := streamRequested(payload, ctx.Headers)

	record := capture.Record{
		TLSIdent: capture.TLSIdentInfo{
			Version: version.Version,
			Commit:  version.Commit,
		},
		Connection: ctx.Connection,
		TLS:        ctx.TLS,
		HTTP2:      ctx.HTTP2,
		HTTP:       extractHTTPInfo(ctx.Method, ctx.Path, ctx.Headers, model),
	}
	snapshot, err := s.store.Append(record)
	if err != nil {
		s.logger.Error("failed to persist capture snapshot", "err", err)
	}
	pretty := mustJSON(snapshot)

	if stream {
		return api.Response{
			StatusCode: 200,
			Headers: map[string]string{
				"content-type":                "text/event-stream",
				"cache-control":               "no-cache",
				"x-accel-buffering":           "no",
				"anthropic-version":           "2023-06-01",
				"x-content-type-options":      "nosniff",
				"access-control-allow-origin": "*",
			},
			Body: messageStreamBody(model, pretty, estimateTokens(payload), estimateTextTokens(pretty)),
		}
	}

	message := map[string]any{
		"id":            fmt.Sprintf("msg_%d", time.Now().UnixNano()),
		"type":          "message",
		"role":          "assistant",
		"model":         defaultModel(model),
		"content":       []map[string]any{{"type": "text", "text": pretty}},
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"usage": map[string]int{
			"input_tokens":  estimateTokens(payload),
			"output_tokens": estimateTextTokens(pretty),
		},
	}
	return jsonResponse(200, message)
}

func (s *Service) countTokens(body []byte) map[string]int {
	payload := parseJSON(body)
	return map[string]int{
		"input_tokens":                estimateTokens(payload),
		"cache_creation_input_tokens": 0,
		"cache_read_input_tokens":     0,
		"output_tokens":               0,
	}
}

func extractHTTPInfo(method, path string, headers map[string][]string, model string) capture.HTTPInfo {
	userAgent := firstHeader(headers, "user-agent")
	return capture.HTTPInfo{
		Program:        inferProgram(userAgent),
		UserAgent:      userAgent,
		Model:          model,
		OS:             firstHeader(headers, "x-stainless-os"),
		Arch:           firstHeader(headers, "x-stainless-arch"),
		Runtime:        firstHeader(headers, "x-stainless-runtime"),
		RuntimeVersion: firstHeader(headers, "x-stainless-runtime-version"),
		Lang:           firstHeader(headers, "x-stainless-lang"),
		SDKVersion:     firstHeader(headers, "x-stainless-package-version"),
		Method:         method,
		Path:           path,
		Headers:        cloneHeaders(headers),
	}
}

func inferProgram(userAgent string) string {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "claude-cli"):
		return "claude-code"
	case strings.Contains(ua, "claude"):
		return "claude"
	default:
		return "unknown"
	}
}

func parseJSON(body []byte) map[string]any {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return map[string]any{}
	}
	return payload
}

func streamRequested(payload map[string]any, headers map[string][]string) bool {
	if value, ok := payload["stream"].(bool); ok {
		return value
	}
	accept := strings.ToLower(firstHeader(headers, "accept"))
	return strings.Contains(accept, "text/event-stream")
}

func defaultModel(model string) string {
	if model != "" {
		return model
	}
	return "claude-sonnet-4-6"
}

func estimateTokens(payload any) int {
	serialized, err := json.Marshal(payload)
	if err != nil {
		return 1
	}
	return estimateTextTokens(string(serialized))
}

func estimateTextTokens(text string) int {
	if text == "" {
		return 1
	}
	return maxInt(1, int(math.Ceil(float64(len(text))/4.0)))
}

func messageStreamBody(model, text string, inputTokens, outputTokens int) []byte {
	messageID := fmt.Sprintf("msg_%d", time.Now().UnixNano())
	var body bytes.Buffer

	writeSSE(&body, "message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id":            messageID,
			"type":          "message",
			"role":          "assistant",
			"model":         defaultModel(model),
			"content":       []any{},
			"stop_reason":   nil,
			"stop_sequence": nil,
			"usage": map[string]int{
				"input_tokens": inputTokens,
			},
		},
	})
	writeSSE(&body, "content_block_start", map[string]any{
		"type":  "content_block_start",
		"index": 0,
		"content_block": map[string]any{
			"type": "text",
			"text": "",
		},
	})
	writeSSE(&body, "content_block_delta", map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]any{
			"type": "text_delta",
			"text": text,
		},
	})
	writeSSE(&body, "content_block_stop", map[string]any{
		"type":  "content_block_stop",
		"index": 0,
	})
	writeSSE(&body, "message_delta", map[string]any{
		"type": "message_delta",
		"delta": map[string]any{
			"stop_reason":   "end_turn",
			"stop_sequence": nil,
		},
		"usage": map[string]int{
			"output_tokens": outputTokens,
		},
	})
	writeSSE(&body, "message_stop", map[string]any{
		"type": "message_stop",
	})

	return body.Bytes()
}

func writeSSE(buf *bytes.Buffer, event string, payload any) {
	data, _ := json.Marshal(payload)
	buf.WriteString("event: ")
	buf.WriteString(event)
	buf.WriteString("\n")
	buf.WriteString("data: ")
	buf.Write(data)
	buf.WriteString("\n\n")
}

func jsonResponse(status int, payload any) api.Response {
	body, _ := json.Marshal(payload)
	return api.Response{
		StatusCode: status,
		Headers: map[string]string{
			"content-type":           "application/json",
			"anthropic-version":      "2023-06-01",
			"x-content-type-options": "nosniff",
		},
		Body: body,
	}
}

func firstHeader(headers map[string][]string, key string) string {
	values := headers[strings.ToLower(key)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func cloneHeaders(headers map[string][]string) map[string][]string {
	cloned := make(map[string][]string, len(headers))
	for key, values := range headers {
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}

func mustJSON(value any) string {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "[]"
	}
	return string(body)
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
