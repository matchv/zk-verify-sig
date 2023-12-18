package signature_verifier

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark/test"

	//"github.com/rs/zerolog"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"

	"testing"
	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
)

func RandomAC[C Interface](t *testing.T, NT int, random func() C) {
	for i := 0; i < NT; i++ {
		fmt.Println(i, " / ", NT)
		item := random()
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(item, item, ecc.BN254.ScalarField()))
	}
}

// go  test -timeout 0s -run ^TestRandomAC -v -tags=debug
func TestRandomAC(t *testing.T) {
	NT := 2
	RandomAC[*Circuit](t, 4*NT, BuildRandom[*Circuit](NewCircuit))
	//RandomAC[*Circuit16](t, NT, BuildRandom[*Circuit16](NewCircuit16))
	//RandomAC[*Circuit32](t, NT, BuildRandom[*Circuit32](NewCircuit32))
	//RandomAC[*Circuit48](t, NT, BuildRandom[*Circuit48](NewCircuit48))
	//RandomAC[*Circuit64](t, NT, BuildRandom[*Circuit64](NewCircuit64))
}

// go  test -timeout 0s -run ^TestSwapRAWA -v

func TestSwapRAWA(t *testing.T) {
	for i := 0; i < 10; i++ {
		R, S, A, Msg := RandomInput(1)
		R, A = A, R
		item := InputToCircuit(NewCircuit(), R, S, A, Msg)
		assert := test.NewAssert(t)
		assert.Error(test.IsSolved(item, item, ecc.BN254.ScalarField()))
	}
}
