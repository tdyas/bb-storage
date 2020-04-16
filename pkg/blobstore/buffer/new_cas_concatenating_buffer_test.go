package buffer_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/buildbarn/bb-storage/internal/mock"
	"github.com/buildbarn/bb-storage/pkg/blobstore/buffer"
	"github.com/buildbarn/bb-storage/pkg/digest"
	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewCASConcatenatingBufferGetSizeBytes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	helloDigest := digest.MustNewDigest("foo", "8b1a9953c4611296a827abf8c47804d7", 5)
	fetcher := mock.NewMockSmallBufferFetcher(ctrl)

	b := buffer.NewCASConcatenatingBuffer(helloDigest, fetcher.Call)
	n, err := b.GetSizeBytes()
	require.NoError(t, err)
	require.Equal(t, int64(5), n)
	b.Discard()
}

func TestNewCASConcatenatingBufferIntoWriter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	helloDigest := digest.MustNewDigest("foo", "8b1a9953c4611296a827abf8c47804d7", 5)

	t.Run("Success", func(t *testing.T) {
		fetcher := mock.NewMockSmallBufferFetcher(ctrl)
		fetcher.EXPECT().Call(int64(0)).
			Return(buffer.NewValidatedBufferFromByteSlice([]byte("He")), int64(0))
		fetcher.EXPECT().Call(int64(2)).
			Return(buffer.NewValidatedBufferFromByteSlice([]byte("l")), int64(2))
		fetcher.EXPECT().Call(int64(3)).
			Return(buffer.NewValidatedBufferFromByteSlice([]byte("lo")), int64(3))
		writer := bytes.NewBuffer(nil)

		err := buffer.NewCASConcatenatingBuffer(helloDigest, fetcher.Call).IntoWriter(writer)
		require.NoError(t, err)
		require.Equal(t, []byte("Hello"), writer.Bytes())
	})

	t.Run("IOError", func(t *testing.T) {
		fetcher := mock.NewMockSmallBufferFetcher(ctrl)
		fetcher.EXPECT().Call(int64(0)).
			Return(buffer.NewBufferFromError(status.Error(codes.Internal, "Storage backend on fire")), int64(0))
		writer := mock.NewMockWriter(ctrl)

		err := buffer.NewCASConcatenatingBuffer(helloDigest, fetcher.Call).IntoWriter(writer)
		require.Equal(t, status.Error(codes.Internal, "Storage backend on fire"), err)
	})
}

func TestNewCASConcatenatingBufferReadAt(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	helloDigest := digest.MustNewDigest("foo", "8b1a9953c4611296a827abf8c47804d7", 5)

	t.Run("Success", func(t *testing.T) {
		fetcher := mock.NewMockSmallBufferFetcher(ctrl)
		fetcher.EXPECT().Call(int64(1)).
			Return(buffer.NewValidatedBufferFromByteSlice([]byte("He")), int64(0))
		fetcher.EXPECT().Call(int64(2)).
			Return(buffer.NewValidatedBufferFromByteSlice([]byte("l")), int64(2))
		fetcher.EXPECT().Call(int64(3)).
			Return(buffer.NewValidatedBufferFromByteSlice([]byte("lo")), int64(3))

		var p [3]byte
		n, err := buffer.NewCASConcatenatingBuffer(helloDigest, fetcher.Call).ReadAt(p[:], 1)
		require.Equal(t, 3, n)
		require.NoError(t, err)
		require.Equal(t, []byte("ell"), p[:])
	})

	t.Run("NegativeOffset", func(t *testing.T) {
		fetcher := mock.NewMockSmallBufferFetcher(ctrl)

		var p [5]byte
		n, err := buffer.NewCASConcatenatingBuffer(helloDigest, fetcher.Call).ReadAt(p[:], -123)
		require.Equal(t, 0, n)
		require.Equal(t, status.Error(codes.InvalidArgument, "Negative read offset: -123"), err)
	})

	t.Run("ReadBeyondEOF", func(t *testing.T) {
		fetcher := mock.NewMockSmallBufferFetcher(ctrl)

		var p [5]byte
		n, err := buffer.NewCASConcatenatingBuffer(helloDigest, fetcher.Call).ReadAt(p[:], 6)
		require.Equal(t, 0, n)
		require.Equal(t, io.EOF, err)
	})

	t.Run("ShortRead", func(t *testing.T) {
		fetcher := mock.NewMockSmallBufferFetcher(ctrl)
		fetcher.EXPECT().Call(int64(2)).
			Return(buffer.NewValidatedBufferFromByteSlice([]byte("l")), int64(2))
		fetcher.EXPECT().Call(int64(3)).
			Return(buffer.NewValidatedBufferFromByteSlice([]byte("lo")), int64(3))

		var p [5]byte
		n, err := buffer.NewCASConcatenatingBuffer(helloDigest, fetcher.Call).ReadAt(p[:], 2)
		require.Equal(t, 3, n)
		require.Equal(t, io.EOF, err)
		require.Equal(t, []byte("llo"), p[:3])
	})

	t.Run("IOFailure", func(t *testing.T) {
		fetcher := mock.NewMockSmallBufferFetcher(ctrl)
		fetcher.EXPECT().Call(int64(1)).
			Return(buffer.NewBufferFromError(status.Error(codes.Internal, "Storage backend on fire")), int64(1))

		var p [2]byte
		n, err := buffer.NewCASConcatenatingBuffer(helloDigest, fetcher.Call).ReadAt(p[:], 1)
		require.Equal(t, 0, n)
		require.Equal(t, status.Error(codes.Internal, "Storage backend on fire"), err)
	})
}

func TestNewCASConcatenatingBufferToActionResult(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Only test the successful case, as other aspects are already
	// covered by TestNewCASBufferFromChunkReaderToReader and other
	// Buffer types.
	t.Run("Exact", func(t *testing.T) {
		fetcher := mock.NewMockSmallBufferFetcher(ctrl)
		fetcher.EXPECT().Call(int64(0)).
			Return(buffer.NewValidatedBufferFromByteSlice(exampleActionResultBytes[:10]), int64(0))
		fetcher.EXPECT().Call(int64(10)).
			Return(buffer.NewValidatedBufferFromByteSlice(exampleActionResultBytes[10:20]), int64(10))
		fetcher.EXPECT().Call(int64(20)).
			Return(buffer.NewValidatedBufferFromByteSlice(exampleActionResultBytes[20:]), int64(20))

		actionResult, err := buffer.NewCASConcatenatingBuffer(exampleActionResultDigest, fetcher.Call).
			ToActionResult(len(exampleActionResultBytes))
		require.NoError(t, err)
		require.True(t, proto.Equal(&exampleActionResultMessage, actionResult))
	})
}

func TestNewCASConcatenatingBufferToByteSlice(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Only test the successful case, as other aspects are already
	// covered by TestNewCASBufferFromChunkReaderToReader and other
	// Buffer types.
	t.Run("Success", func(t *testing.T) {
		fetcher := mock.NewMockSmallBufferFetcher(ctrl)
		fetcher.EXPECT().Call(int64(0)).
			Return(buffer.NewValidatedBufferFromByteSlice([]byte("He")), int64(0))
		fetcher.EXPECT().Call(int64(2)).
			Return(buffer.NewValidatedBufferFromByteSlice([]byte("l")), int64(2))
		fetcher.EXPECT().Call(int64(3)).
			Return(buffer.NewValidatedBufferFromByteSlice([]byte("lo")), int64(3))

		helloDigest := digest.MustNewDigest("foo", "8b1a9953c4611296a827abf8c47804d7", 5)
		data, err := buffer.NewCASConcatenatingBuffer(helloDigest, fetcher.Call).ToByteSlice(10)
		require.NoError(t, err)
		require.Equal(t, []byte("Hello"), data)
	})
}

// TODO

func TestNewCASConcatenatingBufferDiscard(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	fetcher := mock.NewMockSmallBufferFetcher(ctrl)

	buffer.NewCASConcatenatingBuffer(exampleDigest, fetcher.Call).Discard()
}
