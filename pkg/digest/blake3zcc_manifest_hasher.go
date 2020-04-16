package digest

import (
	"hash"

	"github.com/buildbarn/bb-storage/pkg/digest/blake3zcc"
)

type blake3zccManifestHasher struct {
	entry              [blake3zccChunkNodeSizeBytes]byte
	entrySize          int
	chainingValueStack *blake3zcc.ChainingValueStack
	outputSizeBytes    int
}

// newBLAKE3ZCCManifestHasher checksum validates an input sequence with
// BLAKE3ZCC that doesn't simply contain data, but a series of Merkle
// tree nodes. This allows DecomposingBlobAccess to get a validated path
// from blob digest to data contained in an individual block.
func newBLAKE3ZCCManifestHasher(outputSizeBytes int) hash.Hash {
	return &blake3zccManifestHasher{
		chainingValueStack: blake3zcc.NewChainingValueStack(),
		outputSizeBytes:    outputSizeBytes,
	}
}

func (h *blake3zccManifestHasher) Write(p []byte) (int, error) {
	nWritten := len(p)
	for {
		// Copy more data from the input into an internal buffer.
		n := copy(h.entry[h.entrySize:], p)
		p = p[n:]
		h.entrySize += n
		if len(p) == 0 {
			return nWritten, nil
		}

		// The input contains more than 97 additional bytes of
		// data. Because the input consists of a sequence of
		// 64 byte parent nodes, terminated by at most one 97
		// byte chunk node, the input must at this location
		// contain a parent node. Ingest it.
		node := unmarshalBLAKE3ZCCParentNode(h.entry[:])
		h.chainingValueStack.AppendNode(&node)

		// Remove the ingested parent node from the input buffer.
		copy(h.entry[:], h.entry[blake3zccParentNodeSizeBytes:])
		h.entrySize = blake3zccChunkNodeSizeBytes - blake3zccParentNodeSizeBytes
	}
}

func (h *blake3zccManifestHasher) Sum(b []byte) []byte {
	var lastNode blake3zcc.Node
	if h.entrySize == blake3zccChunkNodeSizeBytes {
		// Input ends with a chunk node.
		lastNode = unmarshalBLAKE3ZCCChunkNode(h.entry[:])
	} else if h.entrySize == blake3zccParentNodeSizeBytes {
		// Input ends with a parent node.
		lastNode = unmarshalBLAKE3ZCCParentNode(h.entry[:])
	} else {
		// Input has an invalid size, as it is not 64*n or
		// 64*n+97 bytes in size. As it is not possible to
		// instantiate digest objects of this size and Sum() is
		// only called after size validation, this case should
		// be unreachable.
		panic("Manifest has invalid size")
	}
	rootNode := h.chainingValueStack.GetRootNode(&lastNode)
	return rootNode.GetHashValue(h.outputSizeBytes, b)
}

func (h *blake3zccManifestHasher) Reset() {
	h.entrySize = 0
	h.chainingValueStack = blake3zcc.NewChainingValueStack()
}

func (h *blake3zccManifestHasher) Size() int {
	return h.outputSizeBytes
}

func (h *blake3zccManifestHasher) BlockSize() int {
	return blake3zccParentNodeSizeBytes
}
