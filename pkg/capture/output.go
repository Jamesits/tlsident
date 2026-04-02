package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// DefaultFormatters returns the set of formatters enabled by default.
func DefaultFormatters() []Formatter {
	return []Formatter{JSONFormatter{}, Sub2APIFormatter{}}
}

type OutputWriter struct {
	mu         sync.Mutex
	dir        string
	next       int
	formatters []Formatter
}

func NewOutputWriter(dir string) (*OutputWriter, error) {
	return NewOutputWriterWithFormatters(dir, DefaultFormatters())
}

func NewOutputWriterWithFormatters(dir string, formatters []Formatter) (*OutputWriter, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}
	next, err := nextOutputSequence(dir, formatters)
	if err != nil {
		return nil, err
	}
	return &OutputWriter{dir: dir, next: next, formatters: formatters}, nil
}

func (w *OutputWriter) Write(record Record) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	var firstPath string
	for _, f := range w.formatters {
		path := filepath.Join(w.dir, fmt.Sprintf("%d%s", w.next, f.Suffix()))

		data, err := f.Format(record)
		if err != nil {
			return "", fmt.Errorf("format %s: %w", f.Suffix(), err)
		}

		if err := os.WriteFile(path, data, 0o644); err != nil {
			return "", fmt.Errorf("write output file %s: %w", path, err)
		}

		if firstPath == "" {
			firstPath = path
		}
	}

	w.next++
	return firstPath, nil
}

func nextOutputSequence(dir string, formatters []Formatter) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("read output directory: %w", err)
	}

	suffixes := make([]string, len(formatters))
	for i, f := range formatters {
		suffixes[i] = f.Suffix()
	}

	maxSequence := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		for _, suffix := range suffixes {
			if !strings.HasSuffix(entry.Name(), suffix) {
				continue
			}
			sequence, err := strconv.Atoi(strings.TrimSuffix(entry.Name(), suffix))
			if err != nil || sequence < 1 {
				continue
			}
			if sequence > maxSequence {
				maxSequence = sequence
			}
		}
	}

	return maxSequence + 1, nil
}
