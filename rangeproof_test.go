package kaime

import (
	crand "crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/bulletproof"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestRangeProof25519(t *testing.T) {
	curve := curves.ED25519()
	n := 32
	start1 := time.Now()
	prover, err := bulletproof.NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)

	require.NoError(t, err)
	// value which want to prove
	v := curve.Scalar.New(10)
	gamma := curve.Scalar.Random(crand.Reader)
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	u := curve.Point.Random(crand.Reader)

	transcript := merlin.NewTranscript("test")
	proof, err := prover.Prove(v, gamma, n, g, h, u, transcript)
	duration1 := time.Since(start1)
	fmt.Println("rangeproof25519", duration1)

	start2 := time.Now()
	verifier, err := bulletproof.NewRangeVerifier(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	transcriptVerifier := merlin.NewTranscript("test")
	capV := h.Mul(gamma).Add(g.Mul(v))

	//encodedString := hex.EncodeToString(capV.ToAffineCompressed())
	//fmt.Printf("%v", encodedString)
	verified, err := verifier.Verify(proof, capV, g, h, u, n, transcriptVerifier)
	_ = verified

	duration2 := time.Since(start2)
	fmt.Println("rangeproofverify25519", duration2)
}

func TestRangeProofp256(t *testing.T) {
	curve := getCurve("p256")
	n := 32
	start1 := time.Now()
	prover, err := bulletproof.NewRangeProver(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)

	require.NoError(t, err)
	// value which want to prove
	v := curve.Scalar.New(10)
	gamma := curve.Scalar.Random(crand.Reader)
	g := curve.Point.Random(crand.Reader)
	h := curve.Point.Random(crand.Reader)
	u := curve.Point.Random(crand.Reader)

	transcript := merlin.NewTranscript("test")
	proof, err := prover.Prove(v, gamma, n, g, h, u, transcript)
	duration1 := time.Since(start1)
	fmt.Println("rangeproofproverp256", duration1)

	start2 := time.Now()
	verifier, err := bulletproof.NewRangeVerifier(n, []byte("rangeDomain"), []byte("ippDomain"), *curve)
	require.NoError(t, err)
	transcriptVerifier := merlin.NewTranscript("test")
	capV := h.Mul(gamma).Add(g.Mul(v))

	//encodedString := hex.EncodeToString(capV.ToAffineCompressed())
	//fmt.Printf("%v", encodedString)
	verified, err := verifier.Verify(proof, capV, g, h, u, n, transcriptVerifier)
	_ = verified

	duration2 := time.Since(start2)
	fmt.Println("rangeproofverifyp256", duration2)
}
