package kaime

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

func TestZPp256Init(t *testing.T) {
	curvetype := "P256"
	curve := getCurve(curvetype)
	random := curve.Scalar.Random(rand.Reader)

	v := curve.Scalar.New(0)

	//centralbank key-pair
	centralbank := new(keypair).Create(curvetype)

	cbctx := new(elgamalenc).Create(v, centralbank.pk, random, curvetype)
	start1 := time.Now()
	//centralbank creates zeroproof
	zp := new(zeroproof).Create(cbctx, random, curvetype)
	duration1 := time.Since(start1)
	fmt.Println("zeroprover", duration1)
	//sender sends the proof to on-chain

	start2 := time.Now()
	bool := zeroProofVerify(cbctx, zp, curvetype)
	duration2 := time.Since(start2)
	fmt.Println("zeroverifier", duration2)
	_ = bool
	//fmt.Printf("%t \n", bool)

}
func TestZPed25519Init(t *testing.T) {
	curvetype := "25519"
	curve := getCurve(curvetype)
	random := curve.Scalar.Random(rand.Reader)

	v := curve.Scalar.New(0)

	//centralbank key-pair
	centralbank := new(keypair).Create(curvetype)

	cbctx := new(elgamalenc).Create(v, centralbank.pk, random, curvetype)
	start1 := time.Now()
	//centralbank creates zeroproof
	zp := new(zeroproof).Create(cbctx, random, curvetype)
	duration1 := time.Since(start1)
	fmt.Println("zero25prover", duration1)
	//sender sends the proof to on-chain

	start2 := time.Now()
	bool := zeroProofVerify(cbctx, zp, curvetype)
	duration2 := time.Since(start2)
	fmt.Println("zero25verifier", duration2)
	_ = bool
	//fmt.Printf("%t \n", bool)

}
