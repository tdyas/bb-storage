package blake3zcc

import (
	"encoding/binary"
)

// ChunkParser converts a stream of data to 64 byte blocks. 16 of these
// blocks, 1 KiB of data, are chained and compressed using the BLAKE3
// compression function. The resulting chunk nodes are placed into a
// ChainingValueStack, so that the resulting root node can be extracted
// once all data has been written.
//
// Long story short: it computes the BLAKE3ZCC for a stream of data.
type ChunkParser struct {
	// Construction of the current block.
	block     [maximumBlockSize]byte
	blockSize uint32

	// Construction of the current chunk.
	blocksRemaining    int
	chunkChainingValue [8]uint32
	chunkStart         bool

	// Merkle tree of chunks.
	chainingValueStack *ChainingValueStack
}

// NewChunkParser returns a ChunkParser that is in the initial state.
// This means that calling GetRootNode() on it corresponds to hashing an
// empty byte sequence.
func NewChunkParser() *ChunkParser {
	return &ChunkParser{
		blocksRemaining:    maximumBlocksPerChunk,
		chunkChainingValue: iv,
		chunkStart:         true,
		chainingValueStack: NewChainingValueStack(),
	}
}

func (p *ChunkParser) getBlock() (m [16]uint32) {
	for i := 0; i < len(m); i++ {
		m[i] = binary.LittleEndian.Uint32(p.block[i*4:])
	}
	return
}

// Write data, so that it is inserted into the hasher's state.
func (p *ChunkParser) Write(b []byte) (int, error) {
	nWritten := len(b)
	for {
		// Store more data within the current 64 byte block.
		n := copy(p.block[p.blockSize:], b)
		b = b[n:]
		p.blockSize += uint32(n)
		if len(b) == 0 {
			return nWritten, nil
		}

		// Current 64 byte block is complete.
		m := p.getBlock()
		p.blockSize = 0
		if p.blocksRemaining == 1 {
			// Current 1024 byte chunk is complete. Compute
			// the chunk's chaining value and store it on
			// the chaining value stack.
			n := NewChunkNode(&p.chunkChainingValue, &m, maximumBlockSize, false)
			p.chainingValueStack.AppendNode(&n)

			// Start reading the next 1024 byte chunk.
			p.blocksRemaining = maximumBlocksPerChunk
			p.chunkChainingValue = iv
			p.chunkStart = true
		} else {
			// Current 1024 byte chunk is not complete yet.
			// Continue reading more 64 byte blocks.
			p.blocksRemaining--
			chunkFlags := uint32(0)
			if p.chunkStart {
				chunkFlags |= flagChunkStart
			}
			p.chunkChainingValue = truncate(compress(&p.chunkChainingValue, &m, 0, maximumBlockSize, chunkFlags))
			p.chunkStart = false
		}
	}
}

// GetRootNode returns the root node of the Merkle tree that corresponds
// with all of the data that has been written.
func (p *ChunkParser) GetRootNode() Node {
	// Pad the data in the final 64 byte block with trailing zeroes.
	for i := p.blockSize; i < maximumBlockSize; i++ {
		p.block[i] = 0
	}
	m := p.getBlock()
	n := NewChunkNode(&p.chunkChainingValue, &m, p.blockSize, p.chunkStart)
	return p.chainingValueStack.GetRootNode(&n)
}
