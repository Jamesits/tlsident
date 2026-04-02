package capture

// Formatter defines the interface for output formats.
// Each formatter produces a file with a specific suffix and content encoding.
type Formatter interface {
	// Suffix returns the file extension including the dot (e.g. ".tlsident.json").
	Suffix() string
	// Format serialises a single record into the output byte representation.
	Format(record Record) ([]byte, error)
}
