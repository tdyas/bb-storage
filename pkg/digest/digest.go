package digest

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"
	"strings"

	remoteexecution "github.com/bazelbuild/remote-apis/build/bazel/remote/execution/v2"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Digest holds the identification of an object stored in the Content
// Addressable Storage (CAS) or Action Cache (AC). The use of this
// object is preferred over remoteexecution.Digest for a couple of
// reasons.
//
// - Instances of these objects are guaranteed not to contain any
//   degenerate values. The hash has already been decoded from
//   hexadecimal to binary. The size is non-negative.
// - They keep track of the instance as part of the digest, which allows
//   us to keep function signatures across the codebase simple.
// - They provide utility functions for deriving new digests from them.
//   This ensures that outputs of build actions automatically use the
//   same instance name and hashing algorithm.
//
// Because Digest objects are frequently used as keys (as part of
// caching data structures or to construct sets without duplicate
// values), this implementation immediately constructs a key
// representation upon creation. All functions that extract individual
// components (e.g., GetInstance(), GetHash*() and GetSizeBytes())
// operate directly on the key format.
type Digest struct {
	value string
}

var (
	// BadDigest is a default instance of Digest. It can, for
	// example, be used as a function return value for error cases.
	BadDigest Digest
)

var (
	// SupportedDigestFunctions is the list of digest functions
	// supported by digest.Digest, using the enumeration values that
	// are part of the Remote Execution protocol.
	SupportedDigestFunctions = []remoteexecution.DigestFunction_Value{
		remoteexecution.DigestFunction_BLAKE3ZCC,
		remoteexecution.DigestFunction_MD5,
		remoteexecution.DigestFunction_SHA1,
		remoteexecution.DigestFunction_SHA256,
		remoteexecution.DigestFunction_SHA384,
		remoteexecution.DigestFunction_SHA512,
	}
)

// Unpack the individual hash, size and instance name fields from the
// string representation stored inside the Digest object.
func (d Digest) unpack() (int, int64, int) {
	// Extract the leading hash.
	hashEnd := md5.Size * 2
	for d.value[hashEnd] != '-' {
		hashEnd++
	}

	// Extract the size stored in the middle.
	sizeBytes := int64(0)
	sizeBytesEnd := hashEnd + 1
	for d.value[sizeBytesEnd] != '-' {
		sizeBytes = sizeBytes*10 + int64(d.value[sizeBytesEnd]-'0')
		sizeBytesEnd++
	}

	return hashEnd, sizeBytes, sizeBytesEnd
}

// NewDigest constructs a Digest object from an instance name, hash and
// object size. The instance returned by this function is guaranteed to
// be non-degenerate.
func NewDigest(instance string, hash string, sizeBytes int64) (Digest, error) {
	if strings.HasPrefix(hash, "B3Z:") {
		return newDigestBLAKE3ZCC(instance, hash[4:], sizeBytes)
	}
	if strings.HasPrefix(hash, "B3ZM:") {
		return newDigestBLAKE3ZCCManifest(instance, hash[5:], sizeBytes)
	}
	return newDigestOther(instance, hash, sizeBytes)
}

func newDigestUnchecked(instance string, hash string, sizeBytes int64) Digest {
	return Digest{
		value: fmt.Sprintf("%s-%d-%s", hash, sizeBytes, instance),
	}
}

func newDigestBLAKE3ZCC(instance string, hash string, sizeBytes int64) (Digest, error) {
	// TODO(edsch): Validate the instance name. Maybe have a
	// restrictive character set? What about length?

	// Validate the size.
	if sizeBytes < 0 {
		return BadDigest, status.Errorf(codes.InvalidArgument, "Invalid digest size: %d bytes", sizeBytes)
	}

	// TODO: Validate hash!
	return Digest{
		value: fmt.Sprintf("B3Z:%s-%d-%s", hash, sizeBytes, instance),
	}, nil
}

func newDigestBLAKE3ZCCManifest(instance string, hash string, sizeBytes int64) (Digest, error) {
	// TODO(edsch): Validate the instance name. Maybe have a
	// restrictive character set? What about length?

	// Validate the size.
	if sizeBytes < 0 {
		return BadDigest, status.Errorf(codes.InvalidArgument, "Invalid digest size: %d bytes", sizeBytes)
	}

	// TODO: Validate hash!
	return Digest{
		value: fmt.Sprintf("B3ZM:%s-%d-%s", hash, sizeBytes, instance),
	}, nil
}

func newDigestOther(instance string, hash string, sizeBytes int64) (Digest, error) {
	// TODO(edsch): Validate the instance name. Maybe have a
	// restrictive character set? What about length?

	// Validate the size.
	if sizeBytes < 0 {
		return BadDigest, status.Errorf(codes.InvalidArgument, "Invalid digest size: %d bytes", sizeBytes)
	}

	// Validate the hash.
	if l := len(hash); l != md5.Size*2 && l != sha1.Size*2 &&
		l != sha256.Size*2 && l != sha512.Size384*2 && l != sha512.Size*2 {
		return BadDigest, status.Errorf(codes.InvalidArgument, "Unknown digest hash length: %d characters", l)
	}
	for _, c := range hash {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return BadDigest, status.Errorf(codes.InvalidArgument, "Non-hexadecimal character in digest hash: %#U", c)
		}
	}
	return newDigestUnchecked(instance, hash, sizeBytes), nil
}

// MustNewDigest constructs a Digest similar to NewDigest, but never
// returns an error. Instead, execution will abort if the resulting
// instance would be degenerate. Useful for unit testing.
func MustNewDigest(instance string, hash string, sizeBytes int64) Digest {
	d, err := NewDigest(instance, hash, sizeBytes)
	if err != nil {
		panic(err)
	}
	return d
}

// NewDigestFromPartialDigest constructs a Digest object from an
// instance name and a protocol-level digest object. The instance
// returned by this function is guaranteed to be non-degenerate.
func NewDigestFromPartialDigest(instance string, partialDigest *remoteexecution.Digest) (Digest, error) {
	if partialDigest == nil {
		return BadDigest, status.Error(codes.InvalidArgument, "No digest provided")
	}

	if len(partialDigest.HashBlake3Zcc) > 0 {
		return newDigestBLAKE3ZCC(instance, hex.EncodeToString(partialDigest.HashBlake3Zcc), partialDigest.SizeBytes)
	}
	if len(partialDigest.HashBlake3ZccManifest) > 0 {
		return newDigestBLAKE3ZCCManifest(instance, hex.EncodeToString(partialDigest.HashBlake3ZccManifest), partialDigest.SizeBytes)
	}
	return newDigestOther(instance, partialDigest.HashOther, partialDigest.SizeBytes)
}

// NewDigestFromBytestreamPath creates a Digest from a string having one
// of the following two formats:
//
// - blobs/${hash}/${size}
// - ${instance}/blobs/${hash}/${size}
//
// This notation is used by Bazel to refer to files accessible through a
// gRPC Bytestream service.
func NewDigestFromBytestreamPath(path string) (Digest, error) {
	fields := strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
	l := len(fields)
	if (l != 3 && l != 4) || fields[l-3] != "blobs" {
		return BadDigest, status.Error(codes.InvalidArgument, "Invalid resource naming scheme")
	}
	size, err := strconv.ParseInt(fields[l-1], 10, 64)
	if err != nil {
		return BadDigest, status.Error(codes.InvalidArgument, "Invalid resource naming scheme")
	}
	instance := ""
	if l == 4 {
		instance = fields[0]
	}
	return NewDigest(instance, fields[l-2], size)
}

// NewDerivedDigest creates a Digest object that uses the same instance
// name as the one from which it is derived. This can be used to refer
// to inputs (command, directories, files) of an action.
func (d Digest) NewDerivedDigest(partialDigest *remoteexecution.Digest) (Digest, error) {
	// TODO(edsch): Check whether the resulting digest uses the same
	// hashing algorithm?
	return NewDigestFromPartialDigest(d.GetInstance(), partialDigest)
}

// GetPartialDigest encodes the digest into the format used by the remote
// execution protocol, so that it may be stored in messages returned to
// the client.
func (d Digest) GetPartialDigest() *remoteexecution.Digest {
	hashEnd, sizeBytes, _ := d.unpack()
	hash := d.value[:hashEnd]
	if strings.HasPrefix(hash, "B3Z:") {
		hashBytes, err := hex.DecodeString(hash[4:])
		if err != nil {
			panic("Failed to decode malformed BLAKE3ZCC hash")
		}
		return &remoteexecution.Digest{
			HashBlake3Zcc: hashBytes,
			SizeBytes:     sizeBytes,
		}
	}
	if strings.HasPrefix(hash, "B3ZM:") {
		hashBytes, err := hex.DecodeString(hash[5:])
		if err != nil {
			panic("Failed to decode malformed BLAKE3ZCC manifest hash")
		}
		return &remoteexecution.Digest{
			HashBlake3ZccManifest: hashBytes,
			SizeBytes:             sizeBytes,
		}
	}
	return &remoteexecution.Digest{
		HashOther: hash,
		SizeBytes: sizeBytes,
	}
}

// GetInstance returns the instance name of the object.
func (d Digest) GetInstance() string {
	_, _, sizeBytesEnd := d.unpack()
	return d.value[sizeBytesEnd+1:]
}

// GetHashBytes returns the hash of the object as a slice of bytes.
func (d Digest) GetHashBytes() []byte {
	hashString := d.GetHashString()
	if strings.HasPrefix(hashString, "B3Z:") {
		hashString = hashString[4:]
	}
	if strings.HasPrefix(hashString, "B3ZM:") {
		hashString = hashString[5:]
	}
	hashBytes, err := hex.DecodeString(hashString)
	if err != nil {
		panic("Failed to decode digest hash, even though its contents have already been validated")
	}
	return hashBytes
}

// GetHashString returns the hash of the object as a string.
func (d Digest) GetHashString() string {
	hashEnd, _, _ := d.unpack()
	return d.value[:hashEnd]
}

// GetSizeBytes returns the size of the object, in bytes.
func (d Digest) GetSizeBytes() int64 {
	_, sizeBytes, _ := d.unpack()
	return sizeBytes
}

// KeyFormat is an enumeration type that determines the format of object
// keys returned by Digest.GetKey().
type KeyFormat int

const (
	// KeyWithoutInstance lets Digest.GetKey() return a key that
	// does not include the name of the instance; only the hash and
	// the size.
	KeyWithoutInstance KeyFormat = iota
	// KeyWithInstance lets Digest.GetKey() return a key that
	// includes the hash, size and instance name.
	KeyWithInstance
)

// GetKey generates a string representation of the digest object that
// may be used as keys in hash tables.
func (d Digest) GetKey(format KeyFormat) string {
	switch format {
	case KeyWithoutInstance:
		_, _, sizeBytesEnd := d.unpack()
		return d.value[:sizeBytesEnd]
	case KeyWithInstance:
		return d.value
	default:
		panic("Invalid digest key format")
	}
}

func (d Digest) String() string {
	return d.GetKey(KeyWithInstance)
}

func convertSizeToBlockCount(blobSizeBytes int64, blockSizeBytes int64) int64 {
	return int64((uint64(blobSizeBytes) + uint64(blockSizeBytes) - 1) / uint64(blockSizeBytes))
}

// ToManifest converts a digest object to the digest of its manifest
// object counterpart. Summaries allow large objects to be decomposed
// into a series of concatenate blocks. Manifest objects are stored in
// the CAS as a sequence of digests of their chunks.
//
// It is only possible to create manifest objects when VSO hashing is
// used. This implementation only allows the creation of manifest objects
// for blobs larger than a single block (2 MiB), as storing summaries
// for single block objects would be wasteful.
//
// In addition to returning the digest of the manifest object, this
// function returns a ManifestParser that may be used to extract digests
// from existing summaries or insert digests into new summaries.
func (d Digest) ToManifest(blockSizeBytes int64) (Digest, ManifestParser, bool) {
	if !strings.HasPrefix(d.value, "B3Z:") {
		return BadDigest, nil, false
	}

	// TODO: Check that blockSizeBytes is valid!

	hashEnd, sizeBytes, sizeBytesEnd := d.unpack()
	if sizeBytes <= blockSizeBytes {
		return BadDigest, nil, false
	}

	manifestSizeBytes := convertSizeToBlockCount(sizeBytes, blockSizeBytes) * blake3zccParentNodeSizeBytes
	if lastBlockSizeBytes := sizeBytes % blockSizeBytes; lastBlockSizeBytes > 0 && lastBlockSizeBytes <= 1024 {
		manifestSizeBytes += blake3zccChunkNodeSizeBytes - blake3zccParentNodeSizeBytes
	}
	hash := d.value[4:hashEnd]
	instance := d.value[sizeBytesEnd+1:]
	return Digest{
			value: fmt.Sprintf(
				"B3ZM:%s-%d-%s",
				hash,
				manifestSizeBytes,
				instance),
		},
		newBLAKE3ZCCManifestParser(instance, sizeBytes, blockSizeBytes, len(hash)/2),
		true
}

// NewHasher creates a standard hash.Hash object that may be used to
// compute a checksum of data. The hash.Hash object uses the same
// algorithm as the one that was used to create the digest, making it
// possible to validate data against a digest.
func (d Digest) NewHasher() hash.Hash {
	hash := d.GetHashString()
	if strings.HasPrefix(hash, "B3Z:") {
		return newBLAKE3ZCCBlobHasher(len(hash[4:]) / 2)
	}
	if strings.HasPrefix(hash, "B3ZM:") {
		return newBLAKE3ZCCManifestHasher(len(hash[5:]) / 2)
	}
	switch len(hash) {
	case md5.Size * 2:
		return md5.New()
	case sha1.Size * 2:
		return sha1.New()
	case sha256.Size * 2:
		return sha256.New()
	case sha512.Size384 * 2:
		return sha512.New384()
	case sha512.Size * 2:
		return sha512.New()
	default:
		panic("Digest hash is of unknown type")
	}
}

// NewGenerator creates a writer that may be used to compute digests of
// newly created files.
func (d Digest) NewGenerator() *Generator {
	return &Generator{
		instance:    d.GetInstance(),
		partialHash: d.NewHasher(),
	}
}

// Generator is a writer that may be used to compute digests of newly
// created files.
type Generator struct {
	instance    string
	partialHash hash.Hash
	sizeBytes   int64
}

// Write a chunk of data from a newly created file into the state of the
// Generator.
func (dg *Generator) Write(p []byte) (int, error) {
	n, err := dg.partialHash.Write(p)
	dg.sizeBytes += int64(n)
	return n, err
}

// Sum creates a new digest based on the data written into the
// Generator.
func (dg *Generator) Sum() Digest {
	return newDigestUnchecked(
		dg.instance,
		hex.EncodeToString(dg.partialHash.Sum(nil)),
		dg.sizeBytes)
}
