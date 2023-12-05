package curve_ed25519

import (

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"

	//"github.com/rs/zerolog"

	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"
	crand "crypto/rand"
	"testing"
	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
)

type CircuitSubQ struct { // Test A - Q = A
	A   ElementQ
	B   ElementQ
	Sub ElementQ
}

func (circuit *CircuitSubQ) Define(api frontend.API) error {
	Sub := SubElementQ(circuit.A, circuit.B, api)
	AssertEqualElementQ(Sub, circuit.Sub, api)
	return nil
}

func TestSubQ(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		A0, _ := crand.Int(crand.Reader, Q)
		B0, _ := crand.Int(crand.Reader, Q)
		A := BigIntToElementQ(A0)
		B := BigIntToElementQ(B0)
		Sub := BigIntToElementQ(big.NewInt(0).Sub(A0, B0))
		fmt.Println(A0, " - ", B0, " = ", big.NewInt(0).Sub(A0, B0))
		fmt.Println(A, " - ", B, " = ", Sub)
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(&CircuitSubQ{}, &CircuitSubQ{
			A:   A,
			B:   B,
			Sub: Sub,
		}, ecc.BN254.ScalarField()))
	}
}

type CircuitDivQ struct { // Test A / Q = A
	A   ElementQ
	B   ElementQ
	Div ElementQ
}

func (circuit *CircuitDivQ) Define(api frontend.API) error {
	Div := DivElementQ(circuit.A, circuit.B, api)
	AssertEqualElementQ(Div, circuit.Div, api)
	return nil
}

func TestDivQ(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		A0, _ := crand.Int(crand.Reader, Q)
		B0, _ := crand.Int(crand.Reader, Q)
		A := BigIntToElementQ(A0)
		B := BigIntToElementQ(B0)
		D0 := big.NewInt(0).Mul(A0, big.NewInt(0).ModInverse(B0, Q))
		D0 = big.NewInt(0).Mod(D0, Q)
		Div := BigIntToElementQ(D0)
		fmt.Println(A0, " / ", B0, " = ", D0)
		fmt.Println(A, " / ", B, " = ", Div)
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(&CircuitDivQ{}, &CircuitDivQ{
			A:   A,
			B:   B,
			Div: Div,
		}, ecc.BN254.ScalarField()))
	}
}
