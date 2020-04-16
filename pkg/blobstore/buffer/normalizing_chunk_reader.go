package buffer

import (
	"io"
)

type normalizingChunkReader struct {
	ChunkReader
	minimumChunkSizeBytes int
	maximumChunkSizeBytes int
	lastChunk             []byte
	lastErr               error
}

// newNormalizingChunkReader creates a decorator for ChunkReader that
// normalizes the sizes of the chunks returned by Read(). It causes
// empty chunks to be omitted. Chunks that exceed a provided maximum
// size are decomposed into smaller ones.
func newNormalizingChunkReader(r ChunkReader, chunkPolicy ChunkPolicy) ChunkReader {
	return &normalizingChunkReader{
		ChunkReader:           r,
		minimumChunkSizeBytes: chunkPolicy.minimumSizeBytes,
		maximumChunkSizeBytes: chunkPolicy.maximumSizeBytes,
	}
}

func (r *normalizingChunkReader) readNextChunk() ([]byte, error) {
	if len(r.lastChunk) > 0 {
		// Leftover data from a previous call.
		chunk := r.lastChunk
		r.lastChunk = nil
		return chunk, nil
	}
	if r.lastErr != nil {
		// Stream is already in an error state.
		return nil, r.lastErr
	}
	chunk, err := r.ChunkReader.Read()
	r.lastErr = err
	return chunk, err
}

func (r *normalizingChunkReader) readChunkWithMinimumSize() ([]byte, error) {
	// Fast case: stream returns a chunk that complies to our
	// minimum size requirements.
	chunk, err := r.readNextChunk()
	if err != nil {
		return nil, err
	}
	if len(chunk) >= r.minimumChunkSizeBytes {
		return chunk, nil
	}

	// Slow case: read multiple chunks and concatenate them into a
	// single larger chunk.
	fullChunk := append([]byte{}, chunk...)
	for {
		chunk, err := r.readNextChunk()
		if err == io.EOF && len(fullChunk) > 0 {
			// Final chunk may be smaller than the minimum
			// size limit.
			return fullChunk, nil
		}
		if err != nil {
			return nil, err
		}
		fullChunk = append(fullChunk, chunk...)
		if len(fullChunk) >= r.minimumChunkSizeBytes {
			return fullChunk, nil
		}
	}
}

func (r *normalizingChunkReader) Read() ([]byte, error) {
	chunk, err := r.readChunkWithMinimumSize()
	if err != nil {
		return nil, err
	}
	if len(chunk) > r.maximumChunkSizeBytes {
		// Store excessive data for the next call.
		r.lastChunk = chunk[r.maximumChunkSizeBytes:]
		return chunk[:r.maximumChunkSizeBytes], nil
	}
	return chunk, nil
}
