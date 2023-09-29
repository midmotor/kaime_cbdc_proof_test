package kaime

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

func TestGamalp256Init(t *testing.T) {
	curvetype := "p256"
	curve := getCurve(curvetype)
	random := curve.Scalar.Random(rand.Reader)

	// assume v=10
	v := curve.Scalar.New(10)

	//sender key-pair
	sender := new(keypair).Create(curvetype)

	start := time.Now()

	senderctx := new(elgamalenc).Create(v, sender.pk, random, curvetype)

	_ = senderctx

	duration := time.Since(start)
	fmt.Println("elgamal", duration)
}

func TestGamal25519Init(t *testing.T) {
	curvetype := "25519"
	curve := getCurve(curvetype)
	random := curve.Scalar.Random(rand.Reader)

	// assume v=10
	v := curve.Scalar.New(10)

	//sender key-pair
	sender := new(keypair).Create(curvetype)

	start := time.Now()

	senderctx := new(elgamalenc).Create(v, sender.pk, random, curvetype)

	_ = senderctx

	duration := time.Since(start)
	fmt.Println("25519elgamal", duration)
}
