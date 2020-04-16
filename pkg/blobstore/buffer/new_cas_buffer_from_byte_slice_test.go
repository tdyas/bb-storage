package buffer_test

import (
	"testing"

	"github.com/buildbarn/bb-storage/internal/mock"
	"github.com/buildbarn/bb-storage/pkg/blobstore/buffer"
	"github.com/buildbarn/bb-storage/pkg/digest"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// These tests only cover aspects of NewCASBufferFromByteSlice() itself.
// Testing coverage for the actual behavior of the Buffer object is
// provided by TestNewValidatedBufferFromByteSlice*() and
// TestNewBufferFromError*().

func TestNewCASBufferFromByteSliceSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Simple repetitive sequences of bytes used for test vectors.
	identity251 := make([]byte, 31744)
	for i := 0; i < len(identity251); i++ {
		identity251[i] = byte(i % 251)
	}
	identity256 := make([]byte, 4194305)
	for i := 0; i < len(identity256); i++ {
		identity256[i] = byte(i)
	}

	for hash, body := range map[string][]byte{
		// MD5:
		"8b1a9953c4611296a827abf8c47804d7": []byte("Hello"),
		// SHA-1:
		"a54d88e06612d820bc3be72877c74f257b561b19": []byte("This is a test"),
		// SHA-256:
		"1d1f71aecd9b2d8127e5a91fc871833fffe58c5c63aceed9f6fd0b71fe732504": []byte("And another test"),
		// SHA-384:
		"8eb24e0851260f9ee83e88a47a0ae76871c8c8a8befdfc39931b42a334cd0fcd595e8e6766ef471e5f2d50b74e041e8d": []byte("Even longer checksums"),
		// SHA-512:
		"b1d33bb21db304209f584b55e1a86db38c7c44c466c680c38805db07a92d43260d0e82ffd0a48c337d40372a4ac5b9be1ff24beef2c990e6ea3f2079d067b0e0": []byte("Ridiculously long checksums"),
		// For objects that are 1 KiB in size or less, BLAKE3ZCC
		// should behave identically to regular BLAKE3.
		"B3Z:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d": identity251[:0],
		"B3Z:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262": identity251[:0],
		"B3Z:2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213": identity251[:1],
		"B3Z:e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b": identity251[:63],
		"B3Z:4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98": identity251[:64],
		"B3Z:de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee": identity251[:65],
		"B3Z:10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11": identity251[:1023],
		"B3Z:42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7": identity251[:1024],
		// For objects larger than 1 KiB in size, BLAKE3ZCC
		// behaves differently, because the Chunk Counter is
		// forced to zero.
		"B3Z:c8f3d3293fc52e525bcb33e182a4e160a5bdf219b951bac5e7b41da5c737f1d5": identity251[:1025],
		"B3Z:dfdc7b9119fcedb2a1b4a10e0893b6108e321d3eb48e41063fb7501be23574c4": identity251[:2048],
		"B3Z:12fb39470916244fc07eda262166213d569f9081d7afa1ac28a94f354dd552e0": identity251[:2049],
		"B3Z:cb69b476cc042a7e08cc0fa9192ae77ba6f5ce3cb69edba5f4a9d60358739bff": identity251[:3072],
		"B3Z:916a44123313176d32abf666238c573038a2354488d253eb8b648855d99ed39a": identity251[:3073],
		"B3Z:cbd15819798dcda8a686594582fb0dbe89bc2c053a4caaae9d0ace41d1bd54dc": identity251[:4096],
		"B3Z:e8ff97fb8a92788b1a0c53dad48a0733da5e2b55309e123d728de8628fdeebb7": identity251[:4097],
		"B3Z:0d117afe616b153291e0816e63efb1b56ea332b8203093e4b6cd7bb568f576ed": identity251[:5120],
		"B3Z:e8ff3078cf310f0cb86d073afb4e554a9cc63cf6af511fcdbfa287b4fe16b886": identity251[:5121],
		"B3Z:a94335af53d2929d75b21427e5e899a3ab24c2e770a56bf648e8947fe8c1610f": identity251[:6144],
		"B3Z:60c88fe023626d95e6c2e789893e5e485a63c04631b49bb6747e03c1c76c9152": identity251[:6145],
		"B3Z:eb2bcfb05e14b1cb91fa53f74ba66da50b67cd2516afd50d06769564049149d6": identity251[:7168],
		"B3Z:3e2c8988e56143a62812fe95cc42007ac698ebcfc2047d6e4343c6f5eb178f93": identity251[:7169],
		"B3Z:73c932bec255516b229488d6af3d29fc780e186bcae1b48bbbf8120ecd40cc43": identity251[:8192],
		"B3Z:532faf15320b9b20709d6b74dec46b357f20b0dad1bfde4778e951b2d1556575": identity251[:8193],
		"B3Z:39597ba3974320160842e9be52ecd848d0c999d1a2e07a59d68e4e8f29805fc9": identity251[:16384],
		"B3Z:ab08a58e2f25418bdc944ec1f2cf473d46781e59180952ccc110b69deccb5d70": identity251[:31744],
		// Manifest objects for BLAKE3ZCC hashes.
		"B3ZM:cbd15819798dcda8a686594582fb0dbe89bc2c053a4caaae9d0ace41d1bd54dc": {
			// Parent node for identity251[0:2048].
			0x5c, 0x9e, 0x65, 0x44, 0x11, 0xe3, 0x93, 0xd1, 0xf4, 0xbe, 0xc7, 0x10, 0xcc, 0xd5, 0xbc, 0x56,
			0x69, 0xab, 0x17, 0x7d, 0x61, 0x0a, 0x0e, 0xb6, 0x91, 0xfc, 0xfe, 0xe9, 0x2f, 0xb4, 0xe8, 0xb1,
			0xd0, 0x98, 0xac, 0x7e, 0x5e, 0x0d, 0x84, 0xd2, 0xa8, 0x1d, 0x42, 0x99, 0x1c, 0x2f, 0x88, 0x1a,
			0xc3, 0x7d, 0xd8, 0x0b, 0xea, 0x3f, 0x22, 0x3d, 0xdf, 0x9e, 0x7c, 0x60, 0x31, 0x63, 0x06, 0xf6,
			// Parent node for identity251[2048:4096].
			0x63, 0x91, 0xd0, 0x90, 0x21, 0xe4, 0x9b, 0xeb, 0x97, 0xa3, 0x66, 0x8d, 0x06, 0x16, 0xde, 0x09,
			0x98, 0xbe, 0x38, 0x82, 0x0b, 0x53, 0xaa, 0xb7, 0x58, 0x72, 0x26, 0x47, 0x13, 0x3a, 0xe0, 0xe3,
			0x04, 0xd6, 0xd1, 0x10, 0x51, 0x7a, 0xeb, 0xb2, 0x62, 0x01, 0x02, 0xf6, 0xea, 0x7c, 0xa1, 0x7c,
			0x0b, 0x40, 0x18, 0x3c, 0xb8, 0x37, 0x1c, 0x39, 0xf6, 0x0f, 0x2a, 0x57, 0x99, 0x00, 0xe5, 0x61,
		},
		"B3ZM:12fb39470916244fc07eda262166213d569f9081d7afa1ac28a94f354dd552e0": {
			// Parent node for identity251[0:2048].
			0x5c, 0x9e, 0x65, 0x44, 0x11, 0xe3, 0x93, 0xd1, 0xf4, 0xbe, 0xc7, 0x10, 0xcc, 0xd5, 0xbc, 0x56,
			0x69, 0xab, 0x17, 0x7d, 0x61, 0x0a, 0x0e, 0xb6, 0x91, 0xfc, 0xfe, 0xe9, 0x2f, 0xb4, 0xe8, 0xb1,
			0xd0, 0x98, 0xac, 0x7e, 0x5e, 0x0d, 0x84, 0xd2, 0xa8, 0x1d, 0x42, 0x99, 0x1c, 0x2f, 0x88, 0x1a,
			0xc3, 0x7d, 0xd8, 0x0b, 0xea, 0x3f, 0x22, 0x3d, 0xdf, 0x9e, 0x7c, 0x60, 0x31, 0x63, 0x06, 0xf6,
			// Chunk node for identity251[2048:2049].
			0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5,
			0x7f, 0x52, 0x0e, 0x51, 0x8c, 0x68, 0x05, 0x9b, 0xab, 0xd9, 0x83, 0x1f, 0x19, 0xcd, 0xe0, 0x5b,
			0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x81,
		},
	} {
		digest := digest.MustNewDigest("fedora29", hash, int64(len(body)))
		repairFunc := mock.NewMockRepairFunc(ctrl)

		data, err := buffer.NewCASBufferFromByteSlice(
			digest,
			body,
			buffer.Reparable(digest, repairFunc.Call)).ToByteSlice(len(body))
		require.NoError(t, err)
		require.Equal(t, body, data)
	}
}

func TestNewCASBufferFromByteSliceSizeMismatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	digest := digest.MustNewDigest("ubuntu1804", "8b1a9953c4611296a827abf8c47804d7", 6)
	repairFunc := mock.NewMockRepairFunc(ctrl)
	repairFunc.EXPECT().Call()

	_, err := buffer.NewCASBufferFromByteSlice(
		digest,
		[]byte("Hello"),
		buffer.Reparable(digest, repairFunc.Call)).ToByteSlice(5)
	require.Equal(t, status.Error(codes.Internal, "Buffer is 5 bytes in size, while 6 bytes were expected"), err)
}

func TestNewCASBufferFromByteSliceHashMismatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	digest := digest.MustNewDigest("ubuntu1804", "d41d8cd98f00b204e9800998ecf8427e", 5)
	repairFunc := mock.NewMockRepairFunc(ctrl)
	repairFunc.EXPECT().Call()

	_, err := buffer.NewCASBufferFromByteSlice(
		digest,
		[]byte("Hello"),
		buffer.Reparable(digest, repairFunc.Call)).ToByteSlice(5)
	require.Equal(t, status.Error(codes.Internal, "Buffer has checksum 8b1a9953c4611296a827abf8c47804d7, while d41d8cd98f00b204e9800998ecf8427e was expected"), err)
}
