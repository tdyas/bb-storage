package buffer

import (
	"io"
)

type concatenatingReader struct {
	fetcher   SmallBufferFetcher
	sizeBytes int64

	r      io.ReadCloser
	offset int64
}

// newConcatenatingReader creates a ReadCloser that returns the
// concatenated results of a series of ReadClosers that are dynamically
// obtained by invoking a callback function.
func newConcatenatingReader(fetcher SmallBufferFetcher, sizeBytes int64, offset int64) io.ReadCloser {
	return &concatenatingReader{
		fetcher:   fetcher,
		sizeBytes: sizeBytes,

		r:      newErrorReader(io.EOF),
		offset: offset,
	}
}

func (r *concatenatingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.offset += int64(n)
	if err == io.EOF && r.offset < r.sizeBytes {
		r.r.Close()
		newB, newOffset := r.fetcher(r.offset)
		r.r = newB.ToReader()
		return n, discardFromReader(r.r, newOffset-r.offset)
	}
	return n, err
}

func (r *concatenatingReader) Close() error {
	err := r.r.Close()
	r.r = nil
	return err
}
