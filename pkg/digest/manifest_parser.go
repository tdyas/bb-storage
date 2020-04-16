package digest

type ManifestParser interface {
	GetBlockDigest(manifest []byte, off int64) (blockDigest Digest, actualOffset int64)
	AppendBlockDigest(manifest *[]byte, block []byte) Digest
}
