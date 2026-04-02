package capture

import "sync"

type Store struct {
	mu      sync.RWMutex
	records []Record
	writer  *OutputWriter
}

func NewStore(writer *OutputWriter) *Store {
	return &Store{writer: writer}
}

func (s *Store) Append(record Record) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records = append(s.records, record)
	snapshot := append([]Record(nil), s.records...)
	if s.writer == nil {
		return snapshot, nil
	}
	if _, err := s.writer.Write(record); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func (s *Store) Snapshot() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return append([]Record(nil), s.records...)
}

func (s *Store) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records = nil
}
