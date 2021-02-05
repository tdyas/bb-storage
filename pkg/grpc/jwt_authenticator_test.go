package grpc_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/buildbarn/bb-storage/internal/mock"
	bb_grpc "github.com/buildbarn/bb-storage/pkg/grpc"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestJWTAuthenticator(t *testing.T) {
	ctrl, ctx := gomock.WithContext(context.Background(), t)
	defer ctrl.Finish()
	clock := mock.NewMockClock(ctrl)

	symmetricKey := []byte("0123456789ABCDEF")

	jwtKeys := []bb_grpc.JWTKeyConfig{
		{
			Key: symmetricKey,
		},
	}

	signer := mustMakeSigner(jose.HS256, symmetricKey)

	authenticator := bb_grpc.NewJWTAuthenticator(jwtKeys, clock)

	t.Run("NoGRPC", func(t *testing.T) {
		// Authenticator is used outside of gRPC, meaning it cannot
		// extract request metadata.
		require.Equal(
			t,
			status.Error(codes.Unauthenticated, "Connection was not established using gRPC"),
			authenticator.Authenticate(ctx))
	})

	t.Run("NoAuthorizationMetadata", func(t *testing.T) {
		// Should deny authentication if no `authorization` header is present.
		md := metadata.MD{}
		require.Equal(
			t,
			status.Error(codes.Unauthenticated, "authorization required"),
			authenticator.Authenticate(metadata.NewIncomingContext(ctx, md)),
		)
	})

	t.Run("HasAuthorizationMetadataKeyButNoValues", func(t *testing.T) {
		// Should deny authentication if `authorization` header is present but has no values.
		md := metadata.MD{
			"authorization": nil,
		}
		require.Equal(
			t,
			status.Error(codes.Unauthenticated, "authorization required"),
			authenticator.Authenticate(metadata.NewIncomingContext(ctx, md)),
		)
	})

	t.Run("HasAuthorizationMetadataKeyButMultipleValues", func(t *testing.T) {
		// Should deny authentication if `authorization` header is present and has multiple values.
		md := metadata.Pairs("authorization", "hello", "authorization", "world")
		require.Equal(
			t,
			status.Error(codes.Unauthenticated, "multiple authorization headers are not supported"),
			authenticator.Authenticate(metadata.NewIncomingContext(ctx, md)),
		)
	})

	t.Run("ParsesAndValidateValidJWS", func(t *testing.T) {
		// Should parse and validate a valid JWS.
		clock.EXPECT().Now().Return(time.Unix(1600000000, 0))
		tok, err := jwt.Signed(signer).
			Claims(&jwt.Claims{
				Issuer:  "buildbarn",
				Subject: "subject",
			}).CompactSerialize()
		require.NoError(t, err, "Error creating JWT.")

		md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", tok))
		require.NoError(
			t,
			authenticator.Authenticate(metadata.NewIncomingContext(ctx, md)),
		)
	})

	t.Run("RejectsInvalidJWS", func(t *testing.T) {
		// Should reject an invalid JWS.
		invalidPartsSignedToken := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdWJqZWN0IiwiaXNzIjoiaXNzdWVyIiwic2NvcGVzIjpbInMxIiwiczIiXX0`
		md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", invalidPartsSignedToken))
		require.Equal(
			t,
			status.Error(codes.Unauthenticated, "authorization required: square/go-jose: compact JWS format must have three parts"),
			authenticator.Authenticate(metadata.NewIncomingContext(ctx, md)),
		)
	})

	t.Run("RejectsExpiredJWS", func(t *testing.T) {
		// Should reject an expired JWS.
		clock.EXPECT().Now().Return(time.Unix(1600000000, 0))
		tok, err := jwt.Signed(signer).
			Claims(&jwt.Claims{
				Issuer:  "buildbarn",
				Subject: "subject",
				Expiry:  jwt.NewNumericDate(time.Unix(1599996400, 0)),
			}).CompactSerialize()
		require.NoError(t, err, "Error creating JWT.")

		md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", tok))
		require.Equal(
			t,
			status.Error(codes.Unauthenticated, "authorization required"),
			authenticator.Authenticate(metadata.NewIncomingContext(ctx, md)),
		)
	})
}

func TestJWTAuthenticatorMultipleKeys(t *testing.T) {
	ctrl, ctx := gomock.WithContext(context.Background(), t)
	defer ctrl.Finish()
	clock := mock.NewMockClock(ctrl)

	symmetricKey1 := []byte("0123456789ABCDEF")
	symmetricKey2 := []byte("ABCDEF0123456789")

	jwtKeys := []bb_grpc.JWTKeyConfig{
		{
			Key: symmetricKey1,
		},
		{
			Key: symmetricKey2,
		},
	}

	signer1 := mustMakeSigner(jose.HS256, symmetricKey1)
	signer2 := mustMakeSigner(jose.HS256, symmetricKey2)

	authenticator := bb_grpc.NewJWTAuthenticator(jwtKeys, clock)

	t.Run("ParsesAndValidateValidJWS_Key1", func(t *testing.T) {
		// Should parse and validate a valid JWS.
		clock.EXPECT().Now().Return(time.Unix(1600000000, 0))
		tok, err := jwt.Signed(signer1).
			Claims(&jwt.Claims{
				Issuer:  "buildbarn",
				Subject: "subject",
			}).CompactSerialize()
		require.NoError(t, err, "Error creating JWT.")

		md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", tok))
		require.NoError(
			t,
			authenticator.Authenticate(metadata.NewIncomingContext(ctx, md)),
		)
	})

	t.Run("ParsesAndValidateValidJWS_Key2", func(t *testing.T) {
		// Should parse and validate a valid JWS.
		clock.EXPECT().Now().Return(time.Unix(1600000000, 0))
		tok, err := jwt.Signed(signer2).
			Claims(&jwt.Claims{
				Issuer:  "buildbarn",
				Subject: "subject",
			}).CompactSerialize()
		require.NoError(t, err, "Error creating JWT.")

		md := metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", tok))
		require.NoError(
			t,
			authenticator.Authenticate(metadata.NewIncomingContext(ctx, md)),
		)
	})
}

func mustMakeSigner(alg jose.SignatureAlgorithm, k interface{}) jose.Signer {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: k}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic("failed to create signer:" + err.Error())
	}

	return sig
}
