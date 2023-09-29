package kaime

import (
	"crypto/rand"
	"strings"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

const P256 string = "P256"
const K256 string = "K256"
const ED25519 string = "25519"

type keypair struct {
	sk curves.Scalar
	pk curves.Point
}

func getCurve(s string) *curves.Curve {

	s = strings.ToLower((s))

	if strings.Contains(s, P256) {
		return curves.P256()
	} else if strings.Contains(s, K256) {
		return curves.K256()
	} else if strings.Contains(s, ED25519) {
		return curves.ED25519()
	}
	return curves.K256()
}

func (keys keypair) Create(curvetype string) keypair {
	curve := getCurve(curvetype)
	keys.sk = curve.Scalar.Random(rand.Reader)
	keys.pk = curve.Point.Generator().Mul(keys.sk)

	return keys
}
