package blobstore_test

import (
	"context"
	"math"
	"testing"

	"github.com/buildbarn/bb-storage/internal/mock"
	"github.com/buildbarn/bb-storage/pkg/blobstore"
	"github.com/buildbarn/bb-storage/pkg/blobstore/buffer"
	"github.com/buildbarn/bb-storage/pkg/digest"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDecomposingBlobAccessGet(t *testing.T) {
	ctrl, ctx := gomock.WithContext(context.Background(), t)
	defer ctrl.Finish()

	mockBlobAccess := mock.NewMockBlobAccess(ctrl)
	blobAccess := blobstore.NewDecomposingBlobAccess(mockBlobAccess, 8*1024, 2*1024*1024)

	t.Run("NonBLAKE3ZCC", func(t *testing.T) {
		// Calls for hashing algorithms other than VSO should
		// not get modified. There is no way these can be
		// decomposed into a Merkle tree.
		blobDigest := digest.MustNewDigest(
			"instance",
			"8b1a9953c4611296a827abf8c47804d7",
			5)
		mockBlobAccess.EXPECT().Get(ctx, blobDigest).Return(buffer.NewValidatedBufferFromByteSlice([]byte("Hello")))

		data, err := blobAccess.Get(ctx, blobDigest).ToByteSlice(10)
		require.NoError(t, err)
		require.Equal(t, []byte("Hello"), data)
	})

	t.Run("TooSmall", func(t *testing.T) {
		// With the given configuration, objects that are 8 KiB
		// in size or smaller should not be decomposed.
		identity251 := make([]byte, 8*1024)
		for i := 0; i < len(identity251); i++ {
			identity251[i] = byte(i % 251)
		}
		blobDigest := digest.MustNewDigest(
			"instance",
			"B3Z:73c932bec255516b229488d6af3d29fc",
			8*1024)
		mockBlobAccess.EXPECT().Get(ctx, blobDigest).Return(buffer.NewValidatedBufferFromByteSlice(identity251))

		data, err := blobAccess.Get(ctx, blobDigest).ToByteSlice(8 * 1024)
		require.NoError(t, err)
		require.Equal(t, identity251, data)
	})

	t.Run("TooBig", func(t *testing.T) {
		// A 2 MiB manifest can store 2^15 BLAKE3ZCC parent
		// nodes. As every entry represents 8 KiB of data, this
		// yields a maximum object size of 256 MiB. Storing 1025
		// bytes more than this causes the manifest to contain
		// one more parent node, thus making the manifest 64
		// bytes larger than 2 MiB.
		blobDigest := digest.MustNewDigest(
			"instance",
			"B3Z:5250c4ffd3a728f98862c39c1a754f69",
			256*1024*1024+1025)
		manifestDigest := digest.MustNewDigest(
			"instance",
			"B3ZM:5250c4ffd3a728f98862c39c1a754f69",
			2*1024*1024+64)
		mockChunkReader := mock.NewMockChunkReader(ctrl)
		mockChunkReader.EXPECT().Close()
		mockBlobAccess.EXPECT().Get(ctx, manifestDigest).Return(
			buffer.NewCASBufferFromChunkReader(
				manifestDigest,
				mockChunkReader,
				buffer.Irreparable))

		r := blobAccess.Get(ctx, blobDigest).ToChunkReader(0, buffer.ChunkSizeAtMost(100))
		_, err := r.Read()
		require.Equal(t, status.Error(codes.InvalidArgument, "Failed to load manifest: Buffer is 2097216 bytes in size, while a maximum of 2097152 bytes is permitted"), err)
		r.Close()
	})

	t.Run("Success", func(t *testing.T) {
		// A 16 KiB + 1 B blob should get decomposed into three
		// blocks that are separately stored in the CAS: two of
		// 8 KiB and one of 1 B in size.
		identity251 := make([]byte, 16*1024+1)
		for i := 0; i < len(identity251); i++ {
			identity251[i] = byte(i % 251)
		}
		blobDigest := digest.MustNewDigest(
			"instance",
			"B3Z:091108a2b65e2ae62b852eb3b25296badea4202048daf726e9411bfc12840d0b",
			16*1024+1)
		mockBlobAccess.EXPECT().Get(
			ctx,
			digest.MustNewDigest(
				"instance",
				"B3ZM:091108a2b65e2ae62b852eb3b25296badea4202048daf726e9411bfc12840d0b",
				64+64+97),
		).Return(buffer.NewValidatedBufferFromByteSlice([]byte{
			// Message of first parent node.
			0x65, 0xe4, 0xec, 0x2f, 0x94, 0x07, 0x3d, 0x6e, 0xb0, 0x0a, 0x9b, 0xf5, 0xc0, 0x85, 0xcd, 0xe9,
			0x58, 0xec, 0x73, 0xed, 0x3b, 0xaa, 0xf2, 0xb8, 0x0d, 0x5e, 0x6f, 0x90, 0xdc, 0x86, 0x8e, 0x94,
			0x28, 0x86, 0x21, 0xee, 0x0b, 0xe5, 0x5d, 0x79, 0x56, 0x72, 0x74, 0x5d, 0x01, 0x1e, 0x5b, 0xd7,
			0x0f, 0x9b, 0x43, 0x56, 0x7a, 0x2a, 0xdf, 0x12, 0x38, 0x93, 0x05, 0x3e, 0x85, 0xdf, 0xa9, 0x59,
			// Message of second parent node.
			0x7f, 0x18, 0x44, 0x41, 0x50, 0xfb, 0x61, 0xb8, 0x7a, 0x2f, 0x4e, 0x8e, 0x40, 0x0f, 0x05, 0x00,
			0xfb, 0x88, 0x9a, 0x12, 0xf8, 0x8d, 0xa8, 0xfe, 0xa3, 0xb5, 0xf8, 0x3e, 0xf6, 0x4f, 0x5b, 0x16,
			0xc4, 0x45, 0x27, 0x45, 0x50, 0x32, 0xae, 0x0c, 0x21, 0xaf, 0xae, 0x52, 0xde, 0x96, 0x57, 0x71,
			0xaf, 0x08, 0xf9, 0xa3, 0x1e, 0x92, 0x18, 0x4b, 0x3a, 0x7f, 0x93, 0x10, 0xd6, 0xb1, 0xed, 0x63,
			// Chaining value, message and length of third chunk node.
			0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5,
			0x7f, 0x52, 0x0e, 0x51, 0x8c, 0x68, 0x05, 0x9b, 0xab, 0xd9, 0x83, 0x1f, 0x19, 0xcd, 0xe0, 0x5b,
			0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x81,
		}))
		mockBlobAccess.EXPECT().Get(
			ctx,
			digest.MustNewDigest(
				"instance",
				"B3Z:73c932bec255516b229488d6af3d29fc780e186bcae1b48bbbf8120ecd40cc43",
				8*1024),
		).Return(buffer.NewValidatedBufferFromByteSlice(identity251[:8*1024]))
		mockBlobAccess.EXPECT().Get(
			ctx,
			digest.MustNewDigest(
				"instance",
				"B3Z:316e5d0ac41d22f079fa7a204a657cc1b85343fc6a478c8425d35b06c0b2ddf3",
				8*1024),
		).Return(buffer.NewValidatedBufferFromByteSlice(identity251[8*1024 : 16*1024]))
		mockBlobAccess.EXPECT().Get(
			ctx,
			digest.MustNewDigest(
				"instance",
				"B3Z:ea6f1d357d34988f735500e28867a6b7851b15871edb2bd59c01f139320cab81",
				1),
		).Return(buffer.NewValidatedBufferFromByteSlice(identity251[16*1024:]))

		data, err := blobAccess.Get(ctx, blobDigest).ToByteSlice(16*1024 + 1)
		require.NoError(t, err)
		require.Equal(t, identity251, data)
	})
}

func TestDecomposingBlobAccessPut(t *testing.T) {
	ctrl, ctx := gomock.WithContext(context.Background(), t)
	defer ctrl.Finish()

	mockBlobAccess := mock.NewMockBlobAccess(ctrl)
	blobAccess := blobstore.NewDecomposingBlobAccess(mockBlobAccess, 8*1024, 2*1024*1024)

	t.Run("NonBLAKE3ZCC", func(t *testing.T) {
		// Calls for hashing algorithms other than VSO should
		// not get modified. There is no way these can be
		// decomposed into a Merkle tree.
		blobDigest := digest.MustNewDigest(
			"instance",
			"8b1a9953c4611296a827abf8c47804d7",
			5)
		mockBlobAccess.EXPECT().Put(ctx, blobDigest, gomock.Any()).DoAndReturn(
			func(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
				data, err := b.ToByteSlice(10)
				require.NoError(t, err)
				require.Equal(t, []byte("Hello"), data)
				return nil
			})

		require.NoError(
			t,
			blobAccess.Put(ctx, blobDigest, buffer.NewValidatedBufferFromByteSlice([]byte("Hello"))))
	})

	t.Run("TooSmall", func(t *testing.T) {
		// Blobs that can be stored in a single VSO page (≤ 2 MiB)
		// should not be decomposed, as that would add unnecessary
		// indirection.
		identity251 := make([]byte, 8*1024)
		for i := 0; i < len(identity251); i++ {
			identity251[i] = byte(i % 251)
		}
		blobDigest := digest.MustNewDigest(
			"instance",
			"B3Z:2fce645f446223c12d78b252562eadd9",
			8*1024)
		mockBlobAccess.EXPECT().Put(ctx, blobDigest, gomock.Any()).DoAndReturn(
			func(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
				data, err := b.ToByteSlice(8 * 1024)
				require.NoError(t, err)
				require.Equal(t, identity251, data)
				return nil
			})

		require.NoError(
			t,
			blobAccess.Put(ctx, blobDigest, buffer.NewValidatedBufferFromByteSlice(identity251)))
	})

	t.Run("TooBig", func(t *testing.T) {
		// A 2 MiB manifest can store 2^15 BLAKE3ZCC parent
		// nodes. As every entry represents 8 KiB of data, this
		// yields a maximum object size of 256 MiB. However,
		// storing between 1 and 1024 bytes in the last block
		// means a chunk node is created -- not a parent node.
		// Chunk nodes are larger than parent nodes, meaning we
		// get pushed right over the 2 MiB limit.
		blobDigest := digest.MustNewDigest(
			"instance",
			"B3Z:469516160d23076b433cc1dd5d1dd628",
			256*1024*1024-8*1024+1024)
		r := mock.NewMockChunkReader(ctrl)
		r.EXPECT().Close()

		require.Equal(
			t,
			status.Error(codes.InvalidArgument, "Buffer requires a manifest that is 2097185 bytes in size, while a maximum of 2097152 bytes is permitted"),
			blobAccess.Put(
				ctx,
				blobDigest,
				buffer.NewCASBufferFromChunkReader(
					blobDigest,
					r,
					buffer.UserProvided)))
	})

	t.Run("FarTooBig", func(t *testing.T) {
		// Ensure that manifest size calculation still works with
		// extreme sizes. It should not cause any integer
		// overflows.
		blobDigest := digest.MustNewDigest(
			"instance",
			"B3Z:2fce645f446223c12d78b252562eadd9",
			math.MaxInt64)
		r := mock.NewMockChunkReader(ctrl)
		r.EXPECT().Close()

		require.Equal(
			t,
			status.Error(codes.InvalidArgument, "Buffer requires a manifest that is 72057594037927936 bytes in size, while a maximum of 2097152 bytes is permitted"),
			blobAccess.Put(
				ctx,
				blobDigest,
				buffer.NewCASBufferFromChunkReader(
					blobDigest,
					r,
					buffer.UserProvided)))
	})

	t.Run("Success", func(t *testing.T) {
		// A 16 KiB + 1 B blob should get decomposed into three
		// blocks that are separately stored in the CAS: two of
		// 8 KiB and one of 1 B in size.
		identity251 := make([]byte, 16*1024+1)
		for i := 0; i < len(identity251); i++ {
			identity251[i] = byte(i % 251)
		}
		blobDigest := digest.MustNewDigest(
			"instance",
			"B3Z:091108a2b65e2ae62b852eb3b25296badea4202048daf726e9411bfc12840d0b",
			16*1024+1)
		mockBlobAccess.EXPECT().Put(
			ctx,
			digest.MustNewDigest(
				"instance",
				"B3Z:73c932bec255516b229488d6af3d29fc780e186bcae1b48bbbf8120ecd40cc43",
				8*1024),
			gomock.Any()).DoAndReturn(
			func(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
				data, err := b.ToByteSlice(8 * 1024)
				require.NoError(t, err)
				require.Equal(t, identity251[:8*1024], data)
				return nil
			})
		mockBlobAccess.EXPECT().Put(
			ctx,
			digest.MustNewDigest(
				"instance",
				"B3Z:316e5d0ac41d22f079fa7a204a657cc1b85343fc6a478c8425d35b06c0b2ddf3",
				8*1024),
			gomock.Any()).DoAndReturn(
			func(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
				data, err := b.ToByteSlice(8 * 1024)
				require.NoError(t, err)
				require.Equal(t, identity251[8*1024:16*1024], data)
				return nil
			})
		mockBlobAccess.EXPECT().Put(
			ctx,
			digest.MustNewDigest(
				"instance",
				"B3Z:ea6f1d357d34988f735500e28867a6b7851b15871edb2bd59c01f139320cab81",
				1),
			gomock.Any()).DoAndReturn(
			func(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
				data, err := b.ToByteSlice(10)
				require.NoError(t, err)
				require.Equal(t, identity251[16*1024:], data)
				return nil
			})

		// A manifest should be written into the CAS that
		// contains checksums of all of the blocks written
		// above.
		mockBlobAccess.EXPECT().Put(
			ctx,
			digest.MustNewDigest(
				"instance",
				"B3ZM:091108a2b65e2ae62b852eb3b25296badea4202048daf726e9411bfc12840d0b",
				64+64+97),
			gomock.Any()).DoAndReturn(
			func(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
				data, err := b.ToByteSlice(64 + 64 + 97)
				require.NoError(t, err)
				require.Equal(t, []byte{
					// Message of first parent node.
					0x65, 0xe4, 0xec, 0x2f, 0x94, 0x07, 0x3d, 0x6e, 0xb0, 0x0a, 0x9b, 0xf5, 0xc0, 0x85, 0xcd, 0xe9,
					0x58, 0xec, 0x73, 0xed, 0x3b, 0xaa, 0xf2, 0xb8, 0x0d, 0x5e, 0x6f, 0x90, 0xdc, 0x86, 0x8e, 0x94,
					0x28, 0x86, 0x21, 0xee, 0x0b, 0xe5, 0x5d, 0x79, 0x56, 0x72, 0x74, 0x5d, 0x01, 0x1e, 0x5b, 0xd7,
					0x0f, 0x9b, 0x43, 0x56, 0x7a, 0x2a, 0xdf, 0x12, 0x38, 0x93, 0x05, 0x3e, 0x85, 0xdf, 0xa9, 0x59,
					// Message of second parent node.
					0x7f, 0x18, 0x44, 0x41, 0x50, 0xfb, 0x61, 0xb8, 0x7a, 0x2f, 0x4e, 0x8e, 0x40, 0x0f, 0x05, 0x00,
					0xfb, 0x88, 0x9a, 0x12, 0xf8, 0x8d, 0xa8, 0xfe, 0xa3, 0xb5, 0xf8, 0x3e, 0xf6, 0x4f, 0x5b, 0x16,
					0xc4, 0x45, 0x27, 0x45, 0x50, 0x32, 0xae, 0x0c, 0x21, 0xaf, 0xae, 0x52, 0xde, 0x96, 0x57, 0x71,
					0xaf, 0x08, 0xf9, 0xa3, 0x1e, 0x92, 0x18, 0x4b, 0x3a, 0x7f, 0x93, 0x10, 0xd6, 0xb1, 0xed, 0x63,
					// Chaining value, message and length of third chunk node.
					0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5,
					0x7f, 0x52, 0x0e, 0x51, 0x8c, 0x68, 0x05, 0x9b, 0xab, 0xd9, 0x83, 0x1f, 0x19, 0xcd, 0xe0, 0x5b,
					0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x81,
				}, data)
				return nil
			})

		require.NoError(
			t,
			blobAccess.Put(ctx, blobDigest, buffer.NewValidatedBufferFromByteSlice(identity251)))
	})

	t.Run("FailurePutBlock", func(t *testing.T) {
		// Let the insertion of the second block into the CAS
		// fail. The error message should contain the offset of
		// the block and its digest.
		identity251 := make([]byte, 16*1024)
		for i := 0; i < len(identity251); i++ {
			identity251[i] = byte(i % 251)
		}
		blobDigest := digest.MustNewDigest(
			"instance",
			"B3Z:39597ba3974320160842e9be52ecd848d0c999d1a2e07a59d68e4e8f29805fc9",
			16*1024)
		mockBlobAccess.EXPECT().Put(
			ctx,
			digest.MustNewDigest(
				"instance",
				"B3Z:73c932bec255516b229488d6af3d29fc780e186bcae1b48bbbf8120ecd40cc43",
				8*1024),
			gomock.Any()).DoAndReturn(
			func(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
				data, err := b.ToByteSlice(8 * 1024)
				require.NoError(t, err)
				require.Equal(t, identity251[:8*1024], data)
				return nil
			})
		mockBlobAccess.EXPECT().Put(
			ctx,
			digest.MustNewDigest(
				"instance",
				"B3Z:316e5d0ac41d22f079fa7a204a657cc1b85343fc6a478c8425d35b06c0b2ddf3",
				8*1024),
			gomock.Any()).DoAndReturn(
			func(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
				b.Discard()
				return status.Error(codes.Internal, "Server on fire")
			})

		require.Equal(
			t,
			status.Error(codes.Internal, "Failed to store block at offset 8192 with digest B3Z:316e5d0ac41d22f079fa7a204a657cc1b85343fc6a478c8425d35b06c0b2ddf3-8192-instance: Server on fire"),
			blobAccess.Put(ctx, blobDigest, buffer.NewValidatedBufferFromByteSlice(identity251)))
	})

	t.Run("FailurePutManifest", func(t *testing.T) {
		// Let the insertion of the blocks into the CAS succeed,
		// but the manifest fail.
		identity251 := make([]byte, 16*1024)
		for i := 0; i < len(identity251); i++ {
			identity251[i] = byte(i % 251)
		}
		blobDigest := digest.MustNewDigest(
			"instance",
			"B3Z:39597ba3974320160842e9be52ecd848d0c999d1a2e07a59d68e4e8f29805fc9",
			16*1024)
		mockBlobAccess.EXPECT().Put(
			ctx,
			digest.MustNewDigest(
				"instance",
				"B3Z:73c932bec255516b229488d6af3d29fc780e186bcae1b48bbbf8120ecd40cc43",
				8*1024),
			gomock.Any()).DoAndReturn(
			func(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
				data, err := b.ToByteSlice(8 * 1024)
				require.NoError(t, err)
				require.Equal(t, identity251[:8*1024], data)
				return nil
			})
		mockBlobAccess.EXPECT().Put(
			ctx,
			digest.MustNewDigest(
				"instance",
				"B3Z:316e5d0ac41d22f079fa7a204a657cc1b85343fc6a478c8425d35b06c0b2ddf3",
				8*1024),
			gomock.Any()).DoAndReturn(
			func(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
				data, err := b.ToByteSlice(8 * 1024)
				require.NoError(t, err)
				require.Equal(t, identity251[8*1024:], data)
				return nil
			})
		mockBlobAccess.EXPECT().Put(
			ctx,
			digest.MustNewDigest(
				"instance",
				"B3ZM:39597ba3974320160842e9be52ecd848d0c999d1a2e07a59d68e4e8f29805fc9",
				64+64),
			gomock.Any()).DoAndReturn(
			func(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
				b.Discard()
				return status.Error(codes.Internal, "Server on fire")
			})

		require.Equal(
			t,
			status.Error(codes.Internal, "Failed to store manifest: Server on fire"),
			blobAccess.Put(ctx, blobDigest, buffer.NewValidatedBufferFromByteSlice(identity251)))
	})
}

func TestDecomposingBlobAccessFindMissing(t *testing.T) {
	ctrl, ctx := gomock.WithContext(context.Background(), t)
	defer ctrl.Finish()

	mockBlobAccess := mock.NewMockBlobAccess(ctrl)
	mockBlobAccess.EXPECT().FindMissing(ctx, digest.EmptySet).Return(digest.EmptySet, nil).AnyTimes()
	blobAccess := blobstore.NewDecomposingBlobAccess(mockBlobAccess, 8*1024, 2*1024*1024)

	t.Run("Empty", func(t *testing.T) {
		missing, err := blobAccess.FindMissing(ctx, digest.EmptySet)
		require.NoError(t, err)
		require.Equal(t, digest.EmptySet, missing)
	})

	t.Run("PassthroughSuccess", func(t *testing.T) {
		// Calling FindMissing() with just primitive objects
		// should not generate any additional I/O.
		digests := digest.NewSetBuilder().
			Add(digest.MustNewDigest(
				"hello",
				"185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
				395048301)).
			Add(digest.MustNewDigest(
				"hello",
				"B3Z:2fce645f446223c12d78b252562eadd9",
				8*1024)).
			Build()
		missing := digest.NewSetBuilder().
			Add(digest.MustNewDigest(
				"hello",
				"185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
				395048301)).
			Build()
		mockBlobAccess.EXPECT().FindMissing(ctx, digests).Return(missing, nil)

		actualMissing, err := blobAccess.FindMissing(ctx, digests)
		require.NoError(t, err)
		require.Equal(t, missing, actualMissing)
	})

	t.Run("PassthroughFailure", func(t *testing.T) {
		digests := digest.NewSetBuilder().
			Add(digest.MustNewDigest(
				"hello",
				"185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
				395048301)).
			Build()
		mockBlobAccess.EXPECT().FindMissing(ctx, digests).Return(digest.EmptySet, status.Error(codes.Internal, "Storage on fire"))

		_, err := blobAccess.FindMissing(ctx, digests)
		require.Equal(t, status.Error(codes.Internal, "Storage on fire"), err)
	})

	/*
		t.Run("DecomposingSuccess", func(t *testing.T) {
			// Calling FindMissing() on a composed object should
			// trigger a FindMissing() call against its manifest
			// counterpart. If that exists, it should be loaded from
			// the CAS, followed by calling FindMissing() on all of
			// the block stored inside.
			mockBlobAccess.EXPECT().FindMissing(
				ctx,
				digest.NewSetBuilder().
					Add(digest.MustNewDigest(
						"hello",
						"b9a44a420593fa18453b3be7b63922df43c93ff52d88f2cab26fe1fadba70031ff",
						96)).
					Build(),
			).Return(digest.EmptySet, nil)
			mockBlobAccess.EXPECT().Get(
				ctx,
				digest.MustNewDigest(
					"hello",
					"b9a44a420593fa18453b3be7b63922df43c93ff52d88f2cab26fe1fadba70031ff",
					96)).Return(
				buffer.NewValidatedBufferFromByteSlice(
					[]byte{
						// Hash of first block.
						0xe8, 0xde, 0xef, 0x25, 0xed, 0x53, 0x35, 0x7d,
						0x2a, 0x73, 0x8d, 0x71, 0x56, 0x06, 0x7e, 0x69,
						0x89, 0x2a, 0x7b, 0xdc, 0x19, 0x08, 0x18, 0xcd,
						0x2a, 0xd6, 0x98, 0xa3, 0xa1, 0xf9, 0x5e, 0x03,
						// Hash of second block.
						0xe8, 0xde, 0xef, 0x25, 0xed, 0x53, 0x35, 0x7d,
						0x2a, 0x73, 0x8d, 0x71, 0x56, 0x06, 0x7e, 0x69,
						0x89, 0x2a, 0x7b, 0xdc, 0x19, 0x08, 0x18, 0xcd,
						0x2a, 0xd6, 0x98, 0xa3, 0xa1, 0xf9, 0x5e, 0x03,
						// Hash of third block.
						0x14, 0x06, 0xe0, 0x58, 0x81, 0xe2, 0x99, 0x36,
						0x77, 0x66, 0xd3, 0x13, 0xe2, 0x6c, 0x05, 0x56,
						0x4e, 0xc9, 0x1b, 0xf7, 0x21, 0xd3, 0x17, 0x26,
						0xbd, 0x6e, 0x46, 0xe6, 0x06, 0x89, 0x53, 0x9a,
					}))
			mockBlobAccess.EXPECT().FindMissing(
				ctx,
				digest.NewSetBuilder().
					Add(digest.MustNewDigest(
						"hello",
						"e8deef25ed53357d2a738d7156067e69892a7bdc190818cd2ad698a3a1f95e03fe",
						2*1024*1024)).
					Add(digest.MustNewDigest(
						"hello",
						"1406e05881e299367766d313e26c05564ec91bf721d31726bd6e46e60689539afe",
						1)).
					Build(),
			).Return(digest.EmptySet, nil)

			missing, err := blobAccess.FindMissing(
				ctx,
				digest.NewSetBuilder().
					Add(digest.MustNewDigest(
						"hello",
						"b9a44a420593fa18453b3be7b63922df43c93ff52d88f2cab26fe1fadba7003100",
						4*1024*1024+1)).
					Build())
			require.NoError(t, err)
			require.Equal(t, digest.EmptySet, missing)
		})

		t.Run("DecomposingMissingManifest1", func(t *testing.T) {
			// If the manifest of a composed object is absent, the
			// composed object should be treated absent as well.
			manifestDigests := digest.NewSetBuilder().
				Add(digest.MustNewDigest(
					"hello",
					"b9a44a420593fa18453b3be7b63922df43c93ff52d88f2cab26fe1fadba70031ff",
					96)).
				Build()
			mockBlobAccess.EXPECT().FindMissing(ctx, manifestDigests).Return(manifestDigests, nil)

			blobDigests := digest.NewSetBuilder().
				Add(digest.MustNewDigest(
					"hello",
					"b9a44a420593fa18453b3be7b63922df43c93ff52d88f2cab26fe1fadba7003100",
					4*1024*1024+1)).
				Build()
			missing, err := blobAccess.FindMissing(ctx, blobDigests)
			require.NoError(t, err)
			require.Equal(t, blobDigests, missing)
		})

		t.Run("DecomposingMissingManifest2", func(t *testing.T) {
			// For exceptional circumstances, FindMissing() could
			// report that the manifest is present, while Get() ends
			// up failing with NOT_FOUND regardless. This should get
			// translated to the composed object being absent.
			manifestDigests := digest.NewSetBuilder().
				Add(digest.MustNewDigest(
					"hello",
					"b9a44a420593fa18453b3be7b63922df43c93ff52d88f2cab26fe1fadba70031ff",
					96)).
				Build()
			mockBlobAccess.EXPECT().FindMissing(ctx, manifestDigests).Return(digest.EmptySet, nil)
			mockBlobAccess.EXPECT().Get(
				ctx,
				digest.MustNewDigest(
					"hello",
					"b9a44a420593fa18453b3be7b63922df43c93ff52d88f2cab26fe1fadba70031ff",
					96,
				)).Return(buffer.NewBufferFromError(status.Error(codes.NotFound, "Object not found")))

			blobDigests := digest.NewSetBuilder().
				Add(digest.MustNewDigest(
					"hello",
					"b9a44a420593fa18453b3be7b63922df43c93ff52d88f2cab26fe1fadba7003100",
					4*1024*1024+1)).
				Build()
			missing, err := blobAccess.FindMissing(ctx, blobDigests)
			require.NoError(t, err)
			require.Equal(t, blobDigests, missing)
		})

		t.Run("DecomposingMissingBlock", func(t *testing.T) {
			// If the manifest of a composed object is present in the
			// CAS and it can be loaded successfully, FindMissing()
			// should be called against all of the blocks embedded
			// in the composed object. If one of those is missing,
			// the object should be considered absent.
			manifestDigests := digest.NewSetBuilder().
				Add(digest.MustNewDigest(
					"hello",
					"b9a44a420593fa18453b3be7b63922df43c93ff52d88f2cab26fe1fadba70031ff",
					96)).
				Build()
			mockBlobAccess.EXPECT().FindMissing(ctx, manifestDigests).Return(digest.EmptySet, nil)
			mockBlobAccess.EXPECT().Get(
				ctx,
				digest.MustNewDigest(
					"hello",
					"b9a44a420593fa18453b3be7b63922df43c93ff52d88f2cab26fe1fadba70031ff",
					96)).Return(
				buffer.NewValidatedBufferFromByteSlice(
					[]byte{
						// Hash of first block.
						0xe8, 0xde, 0xef, 0x25, 0xed, 0x53, 0x35, 0x7d,
						0x2a, 0x73, 0x8d, 0x71, 0x56, 0x06, 0x7e, 0x69,
						0x89, 0x2a, 0x7b, 0xdc, 0x19, 0x08, 0x18, 0xcd,
						0x2a, 0xd6, 0x98, 0xa3, 0xa1, 0xf9, 0x5e, 0x03,
						// Hash of second block.
						0xe8, 0xde, 0xef, 0x25, 0xed, 0x53, 0x35, 0x7d,
						0x2a, 0x73, 0x8d, 0x71, 0x56, 0x06, 0x7e, 0x69,
						0x89, 0x2a, 0x7b, 0xdc, 0x19, 0x08, 0x18, 0xcd,
						0x2a, 0xd6, 0x98, 0xa3, 0xa1, 0xf9, 0x5e, 0x03,
						// Hash of third block.
						0x14, 0x06, 0xe0, 0x58, 0x81, 0xe2, 0x99, 0x36,
						0x77, 0x66, 0xd3, 0x13, 0xe2, 0x6c, 0x05, 0x56,
						0x4e, 0xc9, 0x1b, 0xf7, 0x21, 0xd3, 0x17, 0x26,
						0xbd, 0x6e, 0x46, 0xe6, 0x06, 0x89, 0x53, 0x9a,
					}))
			mockBlobAccess.EXPECT().FindMissing(
				ctx,
				digest.NewSetBuilder().
					Add(digest.MustNewDigest(
						"hello",
						"e8deef25ed53357d2a738d7156067e69892a7bdc190818cd2ad698a3a1f95e03fe",
						2*1024*1024)).
					Add(digest.MustNewDigest(
						"hello",
						"1406e05881e299367766d313e26c05564ec91bf721d31726bd6e46e60689539afe",
						1)).
					Build(),
			).Return(
				digest.NewSetBuilder().
					Add(digest.MustNewDigest(
						"hello",
						"1406e05881e299367766d313e26c05564ec91bf721d31726bd6e46e60689539afe",
						1)).
					Build(),
				nil)

			blobDigests := digest.NewSetBuilder().
				Add(digest.MustNewDigest(
					"hello",
					"b9a44a420593fa18453b3be7b63922df43c93ff52d88f2cab26fe1fadba7003100",
					4*1024*1024+1)).
				Build()
			missing, err := blobAccess.FindMissing(ctx, blobDigests)
			require.NoError(t, err)
			require.Equal(t, blobDigests, missing)
		})
	*/
}
