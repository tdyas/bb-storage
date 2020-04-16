package buffer

import (
	"io"

	remoteexecution "github.com/bazelbuild/remote-apis/build/bazel/remote/execution/v2"
	"github.com/buildbarn/bb-storage/pkg/digest"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SmallBufferFetcher is a callback that is provided to
// NewCASConcatenatingBuffer to dynamically obtain backing Buffer
// objects.
//
// The offset provided to this callback is always 0 ≤ x < object size.
// The returned Buffer should at least contain one byte of data at the
// requested offset. In addition to returning a Buffer, this callback
// returns the actual offset at which this Buffer is located within the
// concatenated results.
//
// Because Buffer objects may be cloned, this callback may be invoked
// multiple times. Access is also not synchronized.
type SmallBufferFetcher func(offset int64) (Buffer, int64)

type casConcatenatingBuffer struct {
	digest  digest.Digest
	fetcher SmallBufferFetcher
}

// NewCASConcatenatingBuffer creates a Buffer for a CAS object whose
// contents are backed by multiple Buffer objects that need to be
// concatenated to form the full results.
func NewCASConcatenatingBuffer(digest digest.Digest, fetcher SmallBufferFetcher) Buffer {
	return &casConcatenatingBuffer{
		digest:  digest,
		fetcher: fetcher,
	}
}

func (b *casConcatenatingBuffer) GetSizeBytes() (int64, error) {
	return b.digest.GetSizeBytes(), nil
}

func (b *casConcatenatingBuffer) IntoWriter(w io.Writer) error {
	return intoWriterViaChunkReader(b.ToChunkReader(0, chunkSizeDontCare), w)
}

func (b *casConcatenatingBuffer) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, status.Errorf(codes.InvalidArgument, "Negative read offset: %d", off)
	}
	nTotal := 0
	for {
		if off >= b.digest.GetSizeBytes() {
			return nTotal, io.EOF
		}
		if len(p) == 0 {
			return nTotal, nil
		}

		// Obtain a Buffer that is capable of providing more data.
		smallBuffer, smallBufferOffset := b.fetcher(off)
		n, err := smallBuffer.ReadAt(p, off-smallBufferOffset)
		nTotal += n
		if err != nil && err != io.EOF {
			return nTotal, err
		}
		p = p[n:]
		off += int64(n)
	}
}

func (b *casConcatenatingBuffer) ToActionResult(maximumSizeBytes int) (*remoteexecution.ActionResult, error) {
	return toActionResultViaByteSlice(b, maximumSizeBytes)
}

func (b *casConcatenatingBuffer) ToByteSlice(maximumSizeBytes int) ([]byte, error) {
	return toByteSliceViaReader(b.ToReader(), b.digest, maximumSizeBytes)
}

func (b *casConcatenatingBuffer) ToChunkReader(off int64, chunkPolicy ChunkPolicy) ChunkReader {
	sizeBytes := b.digest.GetSizeBytes()
	if err := validateReaderOffset(sizeBytes, off); err != nil {
		return newErrorChunkReader(err)
	}
	return newNormalizingChunkReader(newConcatenatingChunkReader(b.fetcher, sizeBytes, off), chunkPolicy)
}

func (b *casConcatenatingBuffer) ToReader() io.ReadCloser {
	return newConcatenatingReader(b.fetcher, b.digest.GetSizeBytes(), 0)
}

func (b *casConcatenatingBuffer) CloneCopy(maximumSizeBytes int) (Buffer, Buffer) {
	// This causes both clones to fetch data independently. This is
	// safe, but might be wasteful.
	return b, b
}

func (b *casConcatenatingBuffer) CloneStream() (Buffer, Buffer) {
	return b, b
}

func (b *casConcatenatingBuffer) Discard() {}

func (b *casConcatenatingBuffer) applyErrorHandler(errorHandler ErrorHandler) (replacement Buffer, shouldRetry bool) {
	// Because toUnvalidated*Reader() actually return validated
	// readers for this type, this will cause us to return a Buffer
	// that performs checksum validation at two levels.
	//
	// It isn't safe to eliminate the checksum validation at the top
	// level, because that would allow mixing in corrupted data in
	// case of error retrying.
	return newCASErrorHandlingBuffer(b, errorHandler, b.digest, Irreparable), false
}

func (b *casConcatenatingBuffer) toUnvalidatedChunkReader(off int64, chunkPolicy ChunkPolicy) ChunkReader {
	// Don't allow unvalidated access to underlying data. Return a
	// validated reader. Data inconsistencies should be measured at
	// the lowest level. Otherwise we wouldn't know which corrupted
	// blob to remove from storage.
	return b.ToChunkReader(off, chunkPolicy)
}

func (b *casConcatenatingBuffer) toUnvalidatedReader(off int64) io.ReadCloser {
	sizeBytes := b.digest.GetSizeBytes()
	if err := validateReaderOffset(sizeBytes, off); err != nil {
		return newErrorReader(err)
	}
	return newConcatenatingReader(b.fetcher, sizeBytes, off)
}
