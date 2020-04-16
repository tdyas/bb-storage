package blake3zcc

import (
	"encoding/binary"
)

// Node in the BLAKE3 Merkle tree.
type Node struct {
	chainingValue [8]uint32
	m             [16]uint32
	blockSize     uint32
	flags         uint32
}

// NewChunkNode creates a new Merkle tree node that corresponds to 1 KiB
// of data or less.
func NewChunkNode(chainingValue *[8]uint32, m *[16]uint32, blockSize uint32, chunkStart bool) Node {
	flags := flagChunkEnd
	if chunkStart {
		flags |= flagChunkStart
	}
	return Node{
		chainingValue: *chainingValue,
		m:             *m,
		blockSize:     blockSize,
		flags:         flags,
	}
}

// NewParentNode creates a new Merkle tree node that corresponds to more
// than 1 KiB of data.
func NewParentNode(m *[16]uint32) Node {
	return Node{
		chainingValue: iv,
		m:             *m,
		blockSize:     maximumBlockSize,
		flags:         flagParent,
	}
}

// GetChunkData returns all of the attributes provided to
// NewChunkNode().
func (n *Node) GetChunkData() ([8]uint32, [16]uint32, uint32, bool) {
	if (n.flags & flagChunkEnd) == 0 {
		panic("Node is not a chunk end node")
	}
	return n.chainingValue, n.m, n.blockSize, (n.flags & flagChunkStart) != 0
}

// GetParentData returns all of the attributes provided to
// NewParentNode().
func (n *Node) GetParentData() [16]uint32 {
	if n.flags != flagParent {
		panic("Node is not a parent node")
	}
	return n.m
}

// GetHashValue computes a BLAKE3 hash value that corresponds with the
// provided node. Because BLAKE3 uses an Extendable-Output Function
// (XOF), the amount of data returned is variable, which is why the
// desired output length needs to be specified.
func (n *Node) GetHashValue(outputSizeBytes int, b []byte) []byte {
	l := len(b)
	b = append(b, make([]byte, outputSizeBytes)...)
	out := b[l:]
	counter := uint64(0)
	for len(out) > 0 {
		h := compress(&n.chainingValue, &n.m, counter, n.blockSize, n.flags|flagRoot)
		counter++
		for _, v := range h {
			if len(out) < 4 {
				var x [4]byte
				binary.LittleEndian.PutUint32(x[:], v)
				copy(out, x[:])
				return b
			}
			binary.LittleEndian.PutUint32(out, v)
			out = out[4:]
		}
	}
	return b
}
