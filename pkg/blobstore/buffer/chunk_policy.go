package buffer

// ChunkPolicy is provided as an argument to Buffer.ToChunkReader(). It
// specifies the desired size of chunks returned by ChunkReader.Read().
type ChunkPolicy struct {
	minimumSizeBytes int
	defaultSizeBytes int
	maximumSizeBytes int
}

var (
	// chunkSizeDontCare is used internally for cases where it
	// doesn't really matter what chunk size is used. There is no
	// upper bound on the maximum chunk size, but if no explicit
	// chunk size is known, it will fall back to a size of 64 KiB.
	chunkSizeDontCare = ChunkPolicy{
		minimumSizeBytes: 1,
		defaultSizeBytes: 64 * 1024,
		maximumSizeBytes: int(^uint(0) >> 1),
	}
)

// ChunkSizeExactly can be used if the ChunkReader should return chunks
// of an exact size. Only the final chunk that is returned may be
// smaller than the specified size.  This policy may introduce overhead
// of copying data into contiguous buffers.
func ChunkSizeExactly(sizeBytes int) ChunkPolicy {
	return ChunkPolicy{
		minimumSizeBytes: sizeBytes,
		defaultSizeBytes: sizeBytes,
		maximumSizeBytes: sizeBytes,
	}
}

// ChunkSizeAtMost can be used if the ChunkReader is permitted to return
// chunks that are smaller than the specified size. This policy performs
// the least amount of copying of data.
func ChunkSizeAtMost(sizeBytes int) ChunkPolicy {
	return ChunkPolicy{
		minimumSizeBytes: 1,
		defaultSizeBytes: sizeBytes,
		maximumSizeBytes: sizeBytes,
	}
}
