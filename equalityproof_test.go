package kaime

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

func TestEPp256Init(t *testing.T) {
	curvetype := "P256"
	curve := getCurve(curvetype)
	random := curve.Scalar.Random(rand.Reader)

	// assume v=10
	v := curve.Scalar.New(10)

	//sender key-pair
	sender := new(keypair).Create(curvetype)
	//receiver key-pair
	receiver := new(keypair).Create(curvetype)

	senderctx := new(elgamalenc).Create(v, sender.pk, random, curvetype)
	receiverctx := new(elgamalenc).Create(v, receiver.pk, random, curvetype)
	start1 := time.Now()
	//sender creates equalityproof
	ep := new(equalproof).Create(senderctx, receiverctx, random, curvetype)
	duration1 := time.Since(start1)
	fmt.Println("eqprover", duration1)

	//sender sends the proof to on-chain
	start2 := time.Now()
	bool := equalProofVerify(senderctx, receiverctx, ep, curvetype)
	_ = bool
	duration2 := time.Since(start2)
	fmt.Println("eqverifier", duration2)
	//fmt.Printf("%t \n", bool)

}

func TestEPed25519Init(t *testing.T) {
	curvetype := "25519"
	curve := getCurve(curvetype)
	random := curve.Scalar.Random(rand.Reader)

	// assume v=10
	v := curve.Scalar.New(10)

	//sender key-pair
	sender := new(keypair).Create(curvetype)
	//receiver key-pair
	receiver := new(keypair).Create(curvetype)

	senderctx := new(elgamalenc).Create(v, sender.pk, random, curvetype)
	receiverctx := new(elgamalenc).Create(v, receiver.pk, random, curvetype)

	start1 := time.Now()
	//sender creates equalityproof
	ep := new(equalproof).Create(senderctx, receiverctx, random, curvetype)
	duration1 := time.Since(start1)
	fmt.Println("eq25prover", duration1)
	//sender sends the proof to on-chain

	start2 := time.Now()
	bool := equalProofVerify(senderctx, receiverctx, ep, curvetype)
	_ = bool
	duration2 := time.Since(start2)
	fmt.Println("eq25verifier", duration2)
	//fmt.Printf("%t \n", bool)

}
