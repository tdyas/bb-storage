package blobstore

import (
	"context"
	"io"

	"github.com/buildbarn/bb-storage/pkg/blobstore/buffer"
	"github.com/buildbarn/bb-storage/pkg/digest"
	"github.com/buildbarn/bb-storage/pkg/util"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type decomposingBlobAccess struct {
	base                     BlobAccess
	blockSizeBytes           int
	maximumManifestSizeBytes int
}

// NewDecomposingBlobAccess creates a decorator for BlobAccess that
// decomposes large objects written through this interface into smaller
// blocks. Conversely, large objects read through this interface are
// obtained by concatenating a series of smaller blocks.
//
// This decorator only takes effect when using the VSO hashing
// algorithm. VSO hashing applies SHA-256 at multiple levels
// (64 KiB pages -> 2 MiB blocks -> blob). For VSO, this decorator
// decomposes blobs into 2 MiB blocks. A separate manifest message is
// stored in the CAS that contains checksums of all individual 2 MiB
// blocks, effectively turning all large files into shallow Merkle
// trees.
//
// The goal of this decorator is to place an upper bound on the maximum
// size of objects stored in the CAS. This has several advantages:
//
// - It places a stronger upper bound on the maximum duration of random
//   access reads. This may be useful for use cases that perform lazy
//   loading of content.
// - It allows large blobs to be spread out across shards in case
//   ShardingBlobAccess is used. This may improve distribution of system
//   load and network traffic.
// - It permits workers to access files whose size exceeds the storage
//   capacity of worker-level caches.
func NewDecomposingBlobAccess(base BlobAccess, blockSizeBytes int, maximumManifestSizeBytes int) BlobAccess {
	return &decomposingBlobAccess{
		base:                     base,
		blockSizeBytes:           blockSizeBytes,
		maximumManifestSizeBytes: maximumManifestSizeBytes,
	}
}

func (ba *decomposingBlobAccess) Get(ctx context.Context, digest digest.Digest) buffer.Buffer {
	if manifestDigest, manifestParser, ok := digest.ToManifest(int64(ba.blockSizeBytes)); ok {
		// Obtain the manifest from storage.
		manifest, err := ba.base.Get(ctx, manifestDigest).ToByteSlice(ba.maximumManifestSizeBytes)
		if err != nil {
			return buffer.NewBufferFromError(util.StatusWrap(err, "Failed to load manifest"))
		}

		// Return a Buffer that fetches individual blocks upon
		// access.
		return buffer.NewCASConcatenatingBuffer(
			digest,
			func(offset int64) (buffer.Buffer, int64) {
				blockDigest, blockOffset := manifestParser.GetBlockDigest(manifest, offset)
				return ba.base.Get(ctx, blockDigest), blockOffset
			})
	}
	return ba.base.Get(ctx, digest)
}

func (ba *decomposingBlobAccess) Put(ctx context.Context, digest digest.Digest, b buffer.Buffer) error {
	if manifestDigest, manifestParser, ok := digest.ToManifest(int64(ba.blockSizeBytes)); ok {
		// Read from the input buffer one block at a time.
		r := b.ToChunkReader(0, buffer.ChunkSizeExactly(ba.blockSizeBytes))
		defer r.Close()

		manifestSizeBytes := manifestDigest.GetSizeBytes()
		if manifestSizeBytes > int64(ba.maximumManifestSizeBytes) {
			return status.Errorf(
				codes.InvalidArgument,
				"Buffer requires a manifest that is %d bytes in size, while a maximum of %d bytes is permitted",
				manifestSizeBytes,
				ba.maximumManifestSizeBytes)
		}

		// Store each of the blocks in the CAS separately.
		manifest := make([]byte, 0, manifestSizeBytes)
		offset := int64(0)
		for {
			block, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			blockDigest := manifestParser.AppendBlockDigest(&manifest, block)
			if err := ba.base.Put(
				ctx,
				blockDigest,
				buffer.NewValidatedBufferFromByteSlice(block)); err != nil {
				return util.StatusWrapf(err, "Failed to store block at offset %d with digest %s", offset, blockDigest)
			}
			offset += int64(len(block))
		}

		// Store the manifest that contains digests of all of the
		// blocks in the CAS, so that the blob can be recombined
		// when read. It is safe to use NewValidatedBufferFrom-
		// ByteSlice() here, because checksum validation is
		// already performed against the outer Buffer object.
		if err := ba.base.Put(
			ctx,
			manifestDigest,
			buffer.NewValidatedBufferFromByteSlice(manifest)); err != nil {
			return util.StatusWrap(err, "Failed to store manifest")
		}
		return nil
	}
	return ba.base.Put(ctx, digest, b)
}

type blobToCheck struct {
	blobDigest     digest.Digest
	manifestParser digest.ManifestParser
}

type findMissingQueue struct {
	blobAccess      BlobAccess
	context         context.Context
	missingComposed digest.SetBuilder
	batchSize       int

	pending map[digest.Digest]map[digest.Digest]struct{}
}

func (q *findMissingQueue) add(blockDigest digest.Digest, blobDigest digest.Digest) error {
	// TODO: Limit size of the map-maps!
	if len(q.pending) >= q.batchSize {
		if err := q.finalize(); err != nil {
			return err
		}
		q.pending = map[digest.Digest]map[digest.Digest]struct{}{}
	}

	if _, ok := q.pending[blockDigest]; !ok {
		q.pending[blockDigest] = map[digest.Digest]struct{}{}
	}
	q.pending[blockDigest][blobDigest] = struct{}{}
	return nil
}

func (q *findMissingQueue) finalize() error {
	blockDigests := digest.NewSetBuilder()
	for blockDigest := range q.pending {
		blockDigests.Add(blockDigest)
	}

	missingBlocks, err := q.blobAccess.FindMissing(q.context, blockDigests.Build())
	if err != nil {
		return err
	}

	for _, blockDigest := range missingBlocks.Items() {
		for blobDigest := range q.pending[blockDigest] {
			q.missingComposed.Add(blobDigest)
		}
	}
	return nil
}

func (ba *decomposingBlobAccess) FindMissing(ctx context.Context, digests digest.Set) (digest.Set, error) {
	// Call FindMissing() against the storage backend, but replace
	// all digests of composed objects with ones of their manifest.
	summariesToCheck := map[digest.Digest][]blobToCheck{}
	initialDigests := digest.NewSetBuilder()
	for _, blobDigest := range digests.Items() {
		if manifestDigest, manifestParser, ok := blobDigest.ToManifest(int64(ba.blockSizeBytes)); ok {
			summariesToCheck[manifestDigest] = append(
				summariesToCheck[manifestDigest],
				blobToCheck{
					blobDigest:     blobDigest,
					manifestParser: manifestParser,
				})
			initialDigests.Add(manifestDigest)
		} else {
			initialDigests.Add(blobDigest)
		}
	}
	missingInitially, err := ba.base.FindMissing(ctx, initialDigests.Build())
	if err != nil {
		return digest.EmptySet, err
	}

	// Skip processing blobs of which the manifest is known to be absent.
	missingComposed := digest.NewSetBuilder()
	for _, manifestDigest := range missingInitially.Items() {
		for _, s := range summariesToCheck[manifestDigest] {
			missingComposed.Add(s.blobDigest)
		}
		delete(summariesToCheck, manifestDigest)
	}

	// Load each of the summaries that are present from storage and
	// check whether their blocks are present.
	q := findMissingQueue{
		blobAccess:      ba.base,
		context:         ctx,
		missingComposed: missingComposed,
		// TODO: Parameterize!
		batchSize: 1000,

		pending: map[digest.Digest]map[digest.Digest]struct{}{},
	}
	for manifestDigest, blobsToCheck := range summariesToCheck {
		manifest, err := ba.base.Get(ctx, manifestDigest).ToByteSlice(ba.maximumManifestSizeBytes)
		if err == nil {
			for _, blobToCheck := range blobsToCheck {
				currentOffset := int64(0)
				sizeBytes := blobToCheck.blobDigest.GetSizeBytes()
				for currentOffset < sizeBytes {
					blockDigest, blockOffset := blobToCheck.manifestParser.GetBlockDigest(manifest, currentOffset)
					if err := q.add(blockDigest, blobToCheck.blobDigest); err != nil {
						return digest.EmptySet, err
					}
					currentOffset = blockOffset + blockDigest.GetSizeBytes()
				}
			}
		} else if status.Code(err) == codes.NotFound {
			// Even though FindMissing() previously reported
			// the manifest as present, it was somehow absent
			// after all.
			for _, s := range summariesToCheck[manifestDigest] {
				missingComposed.Add(s.blobDigest)
			}
		} else {
			return digest.EmptySet, util.StatusWrapf(err, "Failed to load manifest %s", manifestDigest)
		}
	}
	if err := q.finalize(); err != nil {
		return digest.EmptySet, err
	}

	// Filter out manifest digests that were added initially, because
	// those were not requested by the user explicitly.
	_, missingInitially, _ = digest.GetDifferenceAndIntersection(missingInitially, digests)
	return digest.GetUnion([]digest.Set{missingInitially, missingComposed.Build()}), nil
}
