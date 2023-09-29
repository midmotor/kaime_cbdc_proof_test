package kaime

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
)

type elgamalenc struct {
	left   curves.Point
	right  curves.Point
	pubkey curves.Point
}

func (cipher elgamalenc) Create(value curves.Scalar, pubkey curves.Point, random curves.Scalar, curvetype string) elgamalenc {
	curve := getCurve(curvetype)

	cipher.pubkey = pubkey

	// ctxleft = r.G
	cipher.left = curve.Point.Generator().Mul(random)
	// ctxleft = v.G + r.PK
	cipher.right = curve.Point.Generator().Mul(value).Add(pubkey.Mul(random))

	return cipher
}
