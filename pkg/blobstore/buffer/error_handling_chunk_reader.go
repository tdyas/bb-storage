package buffer

import (
	"io"
)

type errorHandlingChunkReader struct {
	r            ChunkReader
	errorHandler ErrorHandler
	off          int64
	chunkPolicy  ChunkPolicy
}

// newErrorHandlingChunkReader returns a ChunkReader that forwards calls
// to a reader obtained from a Buffer. Upon I/O failure, it calls into
// an ErrorHandler to request a new Buffer to continue the transfer.
func newErrorHandlingChunkReader(b Buffer, errorHandler ErrorHandler, off int64, chunkPolicy ChunkPolicy) ChunkReader {
	return &errorHandlingChunkReader{
		r:            b.toUnvalidatedChunkReader(off, chunkPolicy),
		errorHandler: errorHandler,
		off:          off,
		chunkPolicy:  chunkPolicy,
	}
}

func (r *errorHandlingChunkReader) Read() ([]byte, error) {
	for {
		chunk, originalErr := r.r.Read()
		if originalErr == nil {
			r.off += int64(len(chunk))
			return chunk, nil
		} else if originalErr == io.EOF {
			return nil, io.EOF
		}
		b, translatedErr := r.errorHandler.OnError(originalErr)
		if translatedErr != nil {
			return nil, translatedErr
		}
		r.r.Close()
		r.r = b.toUnvalidatedChunkReader(r.off, r.chunkPolicy)
	}
}

func (r *errorHandlingChunkReader) Close() {
	r.errorHandler.Done()
	r.r.Close()
}
