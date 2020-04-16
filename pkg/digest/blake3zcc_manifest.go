package digest

import (
	"encoding/binary"

	"github.com/buildbarn/bb-storage/pkg/digest/blake3zcc"
)

// Functions for marshaling and unmarshaling BLAKE3ZCC Merkle tree nodes.
//
// BLAKE3ZCC manifests contain copies of Merkle tree nodes stored in
// binary form. These functions are used both by code that checksum
// validates manifests and extracts individual entries.

const (
	// The size of a serialized BLAKE3ZCC Merkle tree chunk node.
	blake3zccChunkNodeSizeBytes = 97
	// The size of a serialized BLAKE3ZCC Merkle tree parent node.
	blake3zccParentNodeSizeBytes = 64
)

func unmarshalBLAKE3ZCCChunkNode(entry []byte) blake3zcc.Node {
	// Unmarshal the chaining value.
	var chainingValue [8]uint32
	for i := 0; i < len(chainingValue); i++ {
		chainingValue[i] = binary.LittleEndian.Uint32(entry)
		entry = entry[4:]
	}
	// Unmarshal the message.
	var m [16]uint32
	for i := 0; i < len(m); i++ {
		m[i] = binary.LittleEndian.Uint32(entry)
		entry = entry[4:]
	}
	// Unmarshal the block size and chunk start.
	blockSizeBytes := uint32(entry[0] &^ 0x80)
	chunkStart := (entry[0] & 0x80) != 0
	return blake3zcc.NewChunkNode(&chainingValue, &m, blockSizeBytes, chunkStart)
}

func marshalBLAKE3ZCCChunkNode(n *blake3zcc.Node, entry []byte) {
	// Marshal the chaining value.
	chainingValue, m, blockSize, chunkStart := n.GetChunkData()
	for _, v := range chainingValue {
		binary.LittleEndian.PutUint32(entry, v)
		entry = entry[4:]
	}
	// Marshal the message.
	for _, v := range m {
		binary.LittleEndian.PutUint32(entry, v)
		entry = entry[4:]
	}
	// Marshal the block size and chunk start.
	entry[0] = byte(blockSize &^ 0x80)
	if chunkStart {
		entry[0] |= 0x80
	}
}

func unmarshalBLAKE3ZCCParentNode(entry []byte) blake3zcc.Node {
	// Unmarshal the message.
	var m [16]uint32
	for i := 0; i < len(m); i++ {
		m[i] = binary.LittleEndian.Uint32(entry)
		entry = entry[4:]
	}
	return blake3zcc.NewParentNode(&m)
}

func marshalBLAKE3ZCCParentNode(n *blake3zcc.Node, entry []byte) {
	// Marshal the message.
	for _, v := range n.GetParentData() {
		binary.LittleEndian.PutUint32(entry, v)
		entry = entry[4:]
	}
}
