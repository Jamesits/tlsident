package capture

import (
	"encoding/json"
)

// JSONFormatter writes records as indented JSON.
type JSONFormatter struct{}

func (JSONFormatter) Suffix() string { return ".tlsident.json" }

func (JSONFormatter) Format(record Record) ([]byte, error) {
	return json.MarshalIndent(record, "", "  ")
}
