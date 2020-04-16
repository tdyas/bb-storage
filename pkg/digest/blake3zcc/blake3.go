package blake3zcc

import (
	"math/bits"
)

// Constants and algorithms copied from the BLAKE3 specification.
// https://github.com/BLAKE3-team/BLAKE3-specs/raw/master/blake3.pdf

const (
	// Sizes of blocks and chunks that make up BLAKE3's Merkle tree.
	maximumBlockSize      = 64
	maximumBlocksPerChunk = 1024 / 64

	// Values for input d of the BLAKE3 compression function, as
	// specified in table 3 on page 6.
	flagChunkStart uint32 = 1 << 0
	flagChunkEnd   uint32 = 1 << 1
	flagParent     uint32 = 1 << 2
	flagRoot       uint32 = 1 << 3
)

// Initialization vectors, as specified in table 1 on page 5.
var iv = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// The G function, as specified on page 5.
func g(pa *uint32, pb *uint32, pc *uint32, pd *uint32, m0 uint32, m1 uint32) {
	a, b, c, d := *pa, *pb, *pc, *pd
	a += b + m0
	d = bits.RotateLeft32(d^a, -16)
	c += d
	b = bits.RotateLeft32(b^c, -12)
	a += b + m1
	d = bits.RotateLeft32(d^a, -8)
	c += d
	b = bits.RotateLeft32(b^c, -7)
	*pa, *pb, *pc, *pd = a, b, c, d
}

// The compression function, as specified on pages 4 to 6.
//
// TODO: Provide optimized versions that use AVX, SSE, etc.
func compress(h *[8]uint32, m *[16]uint32, t uint64, b uint32, d uint32) [16]uint32 {
	// Initialization, as specified on page 5.
	v := [...]uint32{
		h[0], h[1], h[2], h[3],
		h[4], h[5], h[6], h[7],
		iv[0], iv[1], iv[2], iv[3],
		uint32(t), uint32(t >> 32), b, d,
	}

	// Round 1.
	g(&v[0], &v[4], &v[8], &v[12], m[0], m[1])
	g(&v[1], &v[5], &v[9], &v[13], m[2], m[3])
	g(&v[2], &v[6], &v[10], &v[14], m[4], m[5])
	g(&v[3], &v[7], &v[11], &v[15], m[6], m[7])
	g(&v[0], &v[5], &v[10], &v[15], m[8], m[9])
	g(&v[1], &v[6], &v[11], &v[12], m[10], m[11])
	g(&v[2], &v[7], &v[8], &v[13], m[12], m[13])
	g(&v[3], &v[4], &v[9], &v[14], m[14], m[15])

	// Round 2.
	g(&v[0], &v[4], &v[8], &v[12], m[2], m[6])
	g(&v[1], &v[5], &v[9], &v[13], m[3], m[10])
	g(&v[2], &v[6], &v[10], &v[14], m[7], m[0])
	g(&v[3], &v[7], &v[11], &v[15], m[4], m[13])
	g(&v[0], &v[5], &v[10], &v[15], m[1], m[11])
	g(&v[1], &v[6], &v[11], &v[12], m[12], m[5])
	g(&v[2], &v[7], &v[8], &v[13], m[9], m[14])
	g(&v[3], &v[4], &v[9], &v[14], m[15], m[8])

	// Round 3.
	g(&v[0], &v[4], &v[8], &v[12], m[3], m[4])
	g(&v[1], &v[5], &v[9], &v[13], m[10], m[12])
	g(&v[2], &v[6], &v[10], &v[14], m[13], m[2])
	g(&v[3], &v[7], &v[11], &v[15], m[7], m[14])
	g(&v[0], &v[5], &v[10], &v[15], m[6], m[5])
	g(&v[1], &v[6], &v[11], &v[12], m[9], m[0])
	g(&v[2], &v[7], &v[8], &v[13], m[11], m[15])
	g(&v[3], &v[4], &v[9], &v[14], m[8], m[1])

	// Round 4.
	g(&v[0], &v[4], &v[8], &v[12], m[10], m[7])
	g(&v[1], &v[5], &v[9], &v[13], m[12], m[9])
	g(&v[2], &v[6], &v[10], &v[14], m[14], m[3])
	g(&v[3], &v[7], &v[11], &v[15], m[13], m[15])
	g(&v[0], &v[5], &v[10], &v[15], m[4], m[0])
	g(&v[1], &v[6], &v[11], &v[12], m[11], m[2])
	g(&v[2], &v[7], &v[8], &v[13], m[5], m[8])
	g(&v[3], &v[4], &v[9], &v[14], m[1], m[6])

	// Round 5.
	g(&v[0], &v[4], &v[8], &v[12], m[12], m[13])
	g(&v[1], &v[5], &v[9], &v[13], m[9], m[11])
	g(&v[2], &v[6], &v[10], &v[14], m[15], m[10])
	g(&v[3], &v[7], &v[11], &v[15], m[14], m[8])
	g(&v[0], &v[5], &v[10], &v[15], m[7], m[2])
	g(&v[1], &v[6], &v[11], &v[12], m[5], m[3])
	g(&v[2], &v[7], &v[8], &v[13], m[0], m[1])
	g(&v[3], &v[4], &v[9], &v[14], m[6], m[4])

	// Round 6.
	g(&v[0], &v[4], &v[8], &v[12], m[9], m[14])
	g(&v[1], &v[5], &v[9], &v[13], m[11], m[5])
	g(&v[2], &v[6], &v[10], &v[14], m[8], m[12])
	g(&v[3], &v[7], &v[11], &v[15], m[15], m[1])
	g(&v[0], &v[5], &v[10], &v[15], m[13], m[3])
	g(&v[1], &v[6], &v[11], &v[12], m[0], m[10])
	g(&v[2], &v[7], &v[8], &v[13], m[2], m[6])
	g(&v[3], &v[4], &v[9], &v[14], m[4], m[7])

	// Round 7.
	g(&v[0], &v[4], &v[8], &v[12], m[11], m[15])
	g(&v[1], &v[5], &v[9], &v[13], m[5], m[0])
	g(&v[2], &v[6], &v[10], &v[14], m[1], m[9])
	g(&v[3], &v[7], &v[11], &v[15], m[8], m[6])
	g(&v[0], &v[5], &v[10], &v[15], m[14], m[10])
	g(&v[1], &v[6], &v[11], &v[12], m[2], m[12])
	g(&v[2], &v[7], &v[8], &v[13], m[3], m[4])
	g(&v[3], &v[4], &v[9], &v[14], m[7], m[13])

	// Output of the compression function, as specified on page 6.
	return [...]uint32{
		v[0] ^ v[8], v[1] ^ v[9], v[2] ^ v[10], v[3] ^ v[11],
		v[4] ^ v[12], v[5] ^ v[13], v[6] ^ v[14], v[7] ^ v[15],
		v[8] ^ h[0], v[9] ^ h[1], v[10] ^ h[2], v[11] ^ h[3],
		v[12] ^ h[4], v[13] ^ h[5], v[14] ^ h[6], v[15] ^ h[7],
	}
}

// Truncate the output of the compression function to 256 bits to obtain
// a chaining value.
func truncate(in [16]uint32) (out [8]uint32) {
	copy(out[:], in[:])
	return
}

// Concatenate two chaining values to obtain a parent node message.
func concatenate(a *[8]uint32, b *[8]uint32) (out [16]uint32) {
	copy(out[:], (*a)[:])
	copy(out[8:], (*b)[:])
	return
}
