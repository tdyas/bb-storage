package digest

import (
	"hash"

	"github.com/buildbarn/bb-storage/pkg/digest/blake3zcc"
)

type blake3zccBlobHasher struct {
	p               *blake3zcc.ChunkParser
	outputSizeBytes int
}

// newBLAKE3ZCCBlobHasher creates a hasher for BLAKE3ZCC. BLAKE3ZCC is
// identical to BLAKE3, except that it is computed with the Chunk
// Counter always set to zero. This makes it possible to decompose large
// BLAKE3ZCC hashed files into a Merkle tree of smaller blocks that are
// each BLAKE3ZCC hashed as well.
func newBLAKE3ZCCBlobHasher(outputSizeBytes int) hash.Hash {
	return &blake3zccBlobHasher{
		p:               blake3zcc.NewChunkParser(),
		outputSizeBytes: outputSizeBytes,
	}
}

func (h *blake3zccBlobHasher) Write(p []byte) (int, error) {
	return h.p.Write(p)
}

func (h *blake3zccBlobHasher) Sum(b []byte) []byte {
	n := h.p.GetRootNode()
	return n.GetHashValue(h.outputSizeBytes, b)
}

func (h *blake3zccBlobHasher) Reset() {
	h.p = blake3zcc.NewChunkParser()
}

func (h *blake3zccBlobHasher) Size() int {
	return h.outputSizeBytes
}

func (h *blake3zccBlobHasher) BlockSize() int {
	return 64
}
