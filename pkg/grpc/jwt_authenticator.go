package grpc

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/buildbarn/bb-storage/pkg/clock"
	"github.com/buildbarn/bb-storage/pkg/util"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type JWTKeyConfig struct {
	Key interface{}
}

type jwtAuthenticator struct {
	verifyKeys []JWTKeyConfig
	clock      clock.Clock
}

// From: https://github.com/square/go-jose/blob/v2/jose-util/utils.go
func loadJSONWebKey(json []byte, pub bool) (*jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
	err := jwk.UnmarshalJSON(json)
	if err != nil {
		return nil, err
	}
	// Commenting out due to issue with .Valid returning false on symmetric keys:
	// https://github.com/square/go-jose/issues/314
	// if !jwk.Valid() {
	// 	return nil, errors.New("invalid JWK key")
	// }
	// if jwk.IsPublic() != pub {
	// 	return nil, errors.New("priv/pub JWK key mismatch")
	// }
	return &jwk, nil
}

// LoadJWTPublicKey loads a public key from PEM/DER/JWK-encoded data.
// From: https://github.com/square/go-jose/blob/v2/jose-util/utils.go
func loadJWTPublicKey(data []byte) (interface{}, error) {
	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	// Try to load SubjectPublicKeyInfo
	pub, err0 := x509.ParsePKIXPublicKey(input)
	if err0 == nil {
		return pub, nil
	}

	cert, err1 := x509.ParseCertificate(input)
	if err1 == nil {
		return cert.PublicKey, nil
	}

	jwk, err2 := loadJSONWebKey(data, true)
	if err2 == nil {
		return jwk, nil
	}

	return nil, fmt.Errorf("JWT setup error: parse error, got '%s', '%s' and '%s'", err0, err1, err2)
}

// NewJWTAuthenticator creates an Authenticator that
// only grants access in case a validly-signed JWT (JSON Web Token)
// is passed as a Bearer token in the request's "authorization" header.
func NewJWTAuthenticator(keys []JWTKeyConfig, clock clock.Clock) Authenticator {
	return &jwtAuthenticator{
		verifyKeys: keys,
		clock:      clock,
	}
}

func (a *jwtAuthenticator) Authenticate(ctx context.Context) error {
	// Get the gRPC metadata.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "Connection was not established using gRPC")
	}

	// Extract the `authorization` header.
	// Note: The keys within the metadata are normalized to lowercase.
	//       https://godoc.org/google.golang.org/grpc/metadata#New
	authHeader, ok := md["authorization"]
	if !ok || len(authHeader) < 1 {
		return status.Error(codes.Unauthenticated, "authorization required")
	}

	if len(authHeader) > 1 {
		return status.Error(codes.Unauthenticated, "multiple authorization headers are not supported")
	}

	if !strings.HasPrefix(authHeader[0], "Bearer ") {
		return status.Error(codes.Unauthenticated, "authorization required")
	}

	jwtString := strings.TrimPrefix(authHeader[0], "Bearer ")

	tok, err := jwt.ParseSigned(jwtString)
	if err != nil {
		return util.StatusWrapWithCode(err, codes.Unauthenticated, "authorization required")
	}

	// Verify the signature by trying each of the verification keys in order.
	for _, verifyKey := range a.verifyKeys {
		var claims jwt.Claims
		err = tok.Claims(verifyKey.Key, &claims)
		if err == nil {
			// Signature is valid. Validate the time-related claims.
			// TODO: Validate other claims, e.g. issuer, subject, audience.
			expectedClaims := jwt.Expected{
				Time: a.clock.Now(),
			}
			err = claims.Validate(expectedClaims)
			if err == nil {
				return nil
			} else {
				break
			}
		}
	}

	return status.Error(codes.Unauthenticated, "authorization required")
}
