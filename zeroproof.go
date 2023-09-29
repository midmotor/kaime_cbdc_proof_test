package kaime

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/RadicalApp/libsignal-protocol-go/util/bytehelper"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

type zeroproof struct {
	a1        curves.Point
	a2        curves.Point
	challenge curves.Scalar
	w         curves.Scalar
}

func (zp zeroproof) Create(ctx elgamalenc, r curves.Scalar, curvetype string) zeroproof {
	curve := getCurve(curvetype)
	u := curve.Scalar.Random(rand.Reader)

	// a_1 = u.G
	zp.a1 = curve.Point.Generator().Mul(u)

	// a_2 = u.PK
	zp.a2 = ctx.pubkey.Mul(u)

	// Fiat-Shamir challenge c = hash(G, a1, a2, ctx_left, ctxright)
	c := append(curve.Point.Generator().ToAffineCompressed()[:], zp.a1.ToAffineCompressed()[:]...)
	c = append(c, zp.a2.ToAffineCompressed()[:]...)
	c = append(c, ctx.left.ToAffineCompressed()[:]...)
	c = append(c, ctx.right.ToAffineCompressed()[:]...)
	challenge := sha256.Sum256(c)
	zp.challenge = curve.Scalar.Hash(bytehelper.ArrayToSlice(challenge))

	// w = u + C.r
	zp.w = u.Add(zp.challenge.Mul(r))

	return zp
}

func zeroProofVerify(ctx elgamalenc, zp zeroproof, curvetype string) error {
	curve := getCurve(curvetype)

	// Fiat-Shamir challenge c = hash(G, a1, a2, ctx_left, ctxright)
	c := append(curve.Point.Generator().ToAffineCompressed()[:], zp.a1.ToAffineCompressed()[:]...)
	c = append(c, zp.a2.ToAffineCompressed()[:]...)
	c = append(c, ctx.left.ToAffineCompressed()[:]...)
	c = append(c, ctx.right.ToAffineCompressed()[:]...)
	challenge := sha256.Sum256(c)
	zp.challenge = curve.Scalar.Hash(bytehelper.ArrayToSlice(challenge))

	// w.G
	LHS1 := curve.Point.Generator().Mul(zp.w)

	// a1 + c.ctxleft
	RHS1 := zp.a1.Add(ctx.left.Mul(zp.challenge))

	// w.PK
	LHS2 := ctx.pubkey.Mul(zp.w)

	// a2 + c.ctxright
	RHS2 := zp.a2.Add(ctx.right.Mul(zp.challenge))

	if LHS1.Equal(RHS1) && LHS2.Equal(RHS2) {
		return nil
	} else {
		return errors.New("proof is not valid.")
	}
}
