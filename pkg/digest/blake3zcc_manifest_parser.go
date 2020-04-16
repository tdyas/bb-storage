package digest

import (
	"encoding/hex"
	"fmt"

	"github.com/buildbarn/bb-storage/pkg/digest/blake3zcc"
)

type blake3zccManifestParser struct {
	instance       string
	blobSizeBytes  int64
	blockSizeBytes int64
	hashSizeBytes  int
}

func newBLAKE3ZCCManifestParser(instance string, blobSizeBytes int64, blockSizeBytes int64, hashSizeBytes int) ManifestParser {
	return &blake3zccManifestParser{
		instance:       instance,
		blobSizeBytes:  blobSizeBytes,
		blockSizeBytes: blockSizeBytes,
		hashSizeBytes:  hashSizeBytes,
	}
}

func (mp *blake3zccManifestParser) convertNodeToDigest(n *blake3zcc.Node, blockSizeBytes int64) Digest {
	return Digest{
		value: fmt.Sprintf(
			"B3Z:%s-%d-%s",
			hex.EncodeToString(n.GetHashValue(mp.hashSizeBytes, nil)),
			blockSizeBytes,
			mp.instance),
	}
}

func (mp *blake3zccManifestParser) GetBlockDigest(manifest []byte, off int64) (Digest, int64) {
	// Determine block number of and size of the block.
	block := off / mp.blockSizeBytes
	blockSizeBytes := mp.blockSizeBytes
	if block == convertSizeToBlockCount(mp.blobSizeBytes, mp.blockSizeBytes)-1 {
		blockSizeBytes = mp.blobSizeBytes % mp.blockSizeBytes
	}

	// Extract the Merkle tree node from the manifest.
	entry := manifest[block*blake3zccParentNodeSizeBytes:]
	var n blake3zcc.Node
	if blockSizeBytes <= 1024 {
		n = unmarshalBLAKE3ZCCChunkNode(entry)
	} else {
		n = unmarshalBLAKE3ZCCParentNode(entry)
	}
	return mp.convertNodeToDigest(&n, blockSizeBytes), block * mp.blockSizeBytes
}

func (mp *blake3zccManifestParser) AppendBlockDigest(manifest *[]byte, block []byte) Digest {
	// Compute the Merkle tree node for the block.
	c := blake3zcc.NewChunkParser()
	c.Write(block)
	n := c.GetRootNode()

	// Append the Merkle tree node to the manifest in binary form.
	l := len(*manifest)
	if len(block) <= 1024 {
		*manifest = append(*manifest, make([]byte, blake3zccChunkNodeSizeBytes)...)
		marshalBLAKE3ZCCChunkNode(&n, (*manifest)[l:])
	} else {
		*manifest = append(*manifest, make([]byte, blake3zccParentNodeSizeBytes)...)
		marshalBLAKE3ZCCParentNode(&n, (*manifest)[l:])
	}
	return mp.convertNodeToDigest(&n, int64(len(block)))
}
