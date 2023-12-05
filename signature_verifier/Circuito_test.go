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

/*func TestIntToPoint_1(t *testing.T) {
	P := curve_ed25519IntToPoint(big.NewInt(1))
	fmt.Println(curve_ed25519BX.Cmp(fr.Modulus()))
	fmt.Println(curve_ed25519BY.Cmp(fr.Modulus()))
	if curve_ed25519OnCurve(P.X, P.Y) == false {
		t.Errorf("P is not on curve")
	}
}*/

func RandomAC[C Interface](t *testing.T, NT int, random func() C) {
	for i := 0; i < NT; i++ {
		fmt.Println(i, " / ", NT)
		item := random()
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(item, item, ecc.BN254.ScalarField()))
	}
}

func TestRandomAC(t *testing.T) {
	NT := 2
	RandomAC[*Circuit](t, NT, BuildRandom[*Circuit](NewCircuit))
	RandomAC[*Circuit16](t, NT, BuildRandom[*Circuit16](NewCircuit16))
	RandomAC[*Circuit32](t, NT, BuildRandom[*Circuit32](NewCircuit32))
	RandomAC[*Circuit48](t, NT, BuildRandom[*Circuit48](NewCircuit48))
	RandomAC[*Circuit64](t, NT, BuildRandom[*Circuit64](NewCircuit64))
}

func ShiftSWA[C Interface](t *testing.T, NT int, random func() C) {
	for i := 0; i < NT; i++ {
		fmt.Println(i, " / ", NT)
		item := random()
		S := item.GetS()
		temp := item.GetS()
		for j := 0; j < len(S); j++ {
			S[j] = temp[(j+1)%len(S)]
		}
		item.SetS(S)
		assert := test.NewAssert(t)
		assert.Error(test.IsSolved(item, item, ecc.BN254.ScalarField()))
	}
}

func TestShiftSWA(t *testing.T) {
	NT := 2
	ShiftSWA[*Circuit](t, NT, BuildRandom[*Circuit](NewCircuit))
	ShiftSWA[*Circuit16](t, NT, BuildRandom[*Circuit16](NewCircuit16))
	ShiftSWA[*Circuit32](t, NT, BuildRandom[*Circuit32](NewCircuit32))
	ShiftSWA[*Circuit48](t, NT, BuildRandom[*Circuit48](NewCircuit48))
	ShiftSWA[*Circuit64](t, NT, BuildRandom[*Circuit64](NewCircuit64))
}

func SwapARWA[C Interface](t *testing.T, NT int, random func() C) {
	for i := 0; i < NT; i++ {
		fmt.Println(i, " / ", NT)
		item := random()
		A := item.GetA()
		R := item.GetR()
		item.SetA(R)
		item.SetR(A)
		assert := test.NewAssert(t)
		assert.Error(test.IsSolved(item, item, ecc.BN254.ScalarField()))
	}
}

func TestSwapARWA(t *testing.T) {
	NT := 2
	SwapARWA(t, NT, BuildRandom[*Circuit](NewCircuit))
	SwapARWA(t, NT, BuildRandom[*Circuit16](NewCircuit16))
	SwapARWA(t, NT, BuildRandom[*Circuit32](NewCircuit32))
	SwapARWA(t, NT, BuildRandom[*Circuit48](NewCircuit48))
	SwapARWA(t, NT, BuildRandom[*Circuit64](NewCircuit64))
}
