package buffer

import (
	"io"
)

type concatenatingChunkReader struct {
	fetcher   SmallBufferFetcher
	sizeBytes int64

	r      ChunkReader
	offset int64
}

// newConcatenatingChunkReader creates a ChunkReader that returns the
// concatenated results of a series of ChunkReaders that are dynamically
// obtained by invoking a callback function.
func newConcatenatingChunkReader(fetcher SmallBufferFetcher, sizeBytes int64, offset int64) ChunkReader {
	return &concatenatingChunkReader{
		fetcher:   fetcher,
		sizeBytes: sizeBytes,

		r:      newErrorChunkReader(io.EOF),
		offset: offset,
	}
}

func (r *concatenatingChunkReader) Read() ([]byte, error) {
	for {
		data, err := r.r.Read()
		if err == io.EOF {
			if r.offset >= r.sizeBytes {
				// Actual end-of-file reached.
				return nil, io.EOF
			}
			// End of current buffer reached. Fetch the next one.
			r.r.Close()
			newB, newOffset := r.fetcher(r.offset)
			r.r = newB.ToChunkReader(newOffset-r.offset, chunkSizeDontCare)
		} else if err == nil {
			r.offset += int64(len(data))
			return data, nil
		} else {
			return nil, err
		}
	}
}

func (r *concatenatingChunkReader) Close() {
	r.r.Close()
	r.r = nil
}
