package kaime

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/RadicalApp/libsignal-protocol-go/util/bytehelper"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

type equalproof struct {
	a1        curves.Point
	a2        curves.Point
	challenge curves.Scalar
	w         curves.Scalar
}

func (ep equalproof) Create(ctx1 elgamalenc, ctx2 elgamalenc, r curves.Scalar, curvetype string) equalproof {
	curve := getCurve(curvetype)
	u := curve.Scalar.Random(rand.Reader)

	// a_1 = u.G
	ep.a1 = curve.Point.Generator().Mul(u)

	// a_2 = u.(PK1-PK2)
	ep.a2 = (ctx1.pubkey.Sub(ctx2.pubkey)).Mul(u)

	// Fiat-Shamir challenge c = hash(G, a1, a2, ctx_left, ctx1right, ctx2right)
	c := append(curve.Point.Generator().ToAffineCompressed()[:], ep.a1.ToAffineCompressed()[:]...)
	c = append(c, ep.a2.ToAffineCompressed()[:]...)
	c = append(c, ctx1.left.ToAffineCompressed()[:]...)
	c = append(c, ctx1.right.ToAffineCompressed()[:]...)
	c = append(c, ctx2.right.ToAffineCompressed()[:]...)
	challenge := sha256.Sum256(c)
	ep.challenge = curve.Scalar.Hash(bytehelper.ArrayToSlice(challenge))

	// w = u + C.r
	ep.w = u.Add(ep.challenge.Mul(r))

	return ep
}

func equalProofVerify(ctx1 elgamalenc, ctx2 elgamalenc, ep equalproof, curvetype string) error {
	curve := getCurve(curvetype)

	// Fiat-Shamir challenge c = hash(G, a1, a2, ctx_left, ctx1right, ctx2right)
	c := append(curve.Point.Generator().ToAffineCompressed()[:], ep.a1.ToAffineCompressed()[:]...)
	c = append(c, ep.a2.ToAffineCompressed()[:]...)
	c = append(c, ctx1.left.ToAffineCompressed()[:]...)
	c = append(c, ctx1.right.ToAffineCompressed()[:]...)
	c = append(c, ctx2.right.ToAffineCompressed()[:]...)
	challenge := sha256.Sum256(c)
	ep.challenge = curve.Scalar.Hash(bytehelper.ArrayToSlice(challenge))

	// w.G
	LHS1 := curve.Point.Generator().Mul(ep.w)

	// a1 + c.ctx1left
	RHS1 := ep.a1.Add(ctx1.left.Mul(ep.challenge))

	// w.(PK1-PK2)
	LHS2 := (ctx1.pubkey.Sub(ctx2.pubkey)).Mul(ep.w)

	// a2 + c.(ctx1right- ctx2right)
	RHS2 := ep.a2.Add((ctx1.right.Sub(ctx2.right)).Mul(ep.challenge))

	if LHS1.Equal(RHS1) && LHS2.Equal(RHS2) {
		return nil
	} else {
		return errors.New("proof is not valid.")
	}
}
