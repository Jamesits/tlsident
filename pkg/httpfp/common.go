package httpfp

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/net/http2"

	"tlsident/pkg/capture"
)

type HTTP2Tracker struct {
	settings          []http2.Setting
	windowUpdate      uint32
	priorities        []PriorityFrame
	pseudoHeaderOrder []string
}

type PriorityFrame struct {
	StreamID uint32
	http2.PriorityParam
}

func (t *HTTP2Tracker) RecordSettings(frame *http2.SettingsFrame) error {
	if len(t.settings) > 0 {
		return nil
	}
	return frame.ForeachSetting(func(setting http2.Setting) error {
		t.settings = append(t.settings, setting)
		return nil
	})
}

func (t *HTTP2Tracker) RecordWindowUpdate(increment uint32) {
	if t.windowUpdate == 0 {
		t.windowUpdate = increment
	}
}

func (t *HTTP2Tracker) RecordPriority(priority PriorityFrame) {
	if len(t.priorities) < 32 {
		t.priorities = append(t.priorities, priority)
	}
}

func (t *HTTP2Tracker) RecordPseudoHeaderOrder(headers []HeaderField) {
	if len(t.pseudoHeaderOrder) > 0 {
		return
	}
	for _, header := range headers {
		if strings.HasPrefix(header.Name, ":") {
			t.pseudoHeaderOrder = append(t.pseudoHeaderOrder, pseudoHeaderToken(header.Name))
		}
	}
}

func (t *HTTP2Tracker) Snapshot() capture.HTTP2Info {
	settings := formatSettings(t.settings)
	windowUpdate := "00"
	if t.windowUpdate != 0 {
		windowUpdate = strconv.FormatUint(uint64(t.windowUpdate), 10)
	}
	priorities := formatPriorities(t.priorities)
	pseudoHeaders := strings.Join(t.pseudoHeaderOrder, ",")
	fingerprint := fmt.Sprintf("%s|%s|%s|%s", settings, windowUpdate, priorities, pseudoHeaders)
	return capture.HTTP2Info{
		Fingerprint:       fingerprint,
		AkamaiFingerprint: fingerprint,
	}
}

func formatSettings(settings []http2.Setting) string {
	parts := make([]string, 0, len(settings))
	for _, setting := range settings {
		parts = append(parts, fmt.Sprintf("%d:%d", setting.ID, setting.Val))
	}
	return strings.Join(parts, ";")
}

func formatPriorities(priorities []PriorityFrame) string {
	if len(priorities) == 0 {
		return "0"
	}
	parts := make([]string, 0, len(priorities))
	for _, priority := range priorities {
		exclusive := 0
		if priority.Exclusive {
			exclusive = 1
		}
		parts = append(parts, fmt.Sprintf("%d:%d:%d:%d", priority.StreamID, exclusive, priority.StreamDep, priority.Weight))
	}
	return strings.Join(parts, ",")
}

func pseudoHeaderToken(name string) string {
	switch name {
	case ":method":
		return "m"
	case ":path":
		return "p"
	case ":authority":
		return "a"
	case ":scheme":
		return "s"
	default:
		return strings.TrimPrefix(name, ":")
	}
}

func normalizeHeaderMap(source map[string][]string) map[string][]string {
	normalized := make(map[string][]string, len(source))
	for key, values := range source {
		normalized[strings.ToLower(key)] = append([]string(nil), values...)
	}
	return normalized
}

func firstHeaderValue(headers map[string][]string, key string) string {
	values := headers[strings.ToLower(key)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

type HeaderField struct {
	Name  string
	Value string
}
