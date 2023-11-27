package Curve

import (

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"

	//"github.com/rs/zerolog"

	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"
	crand "crypto/rand"
	"testing"
	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
)

type CircuitEqualSum struct { // Test A + B = Sum
	A   PointCircuit `gnark:",public"`
	B   PointCircuit `gnark:",public"`
	Sum PointCircuit `gnark:",public"`
}

func (circuit *CircuitEqualSum) Define(api frontend.API) error {
	AB := AddCircuit(circuit.A, circuit.B, api)
	api.AssertIsEqual(AB.X, circuit.Sum.X)
	api.AssertIsEqual(AB.Y, circuit.Sum.Y)
	return nil
}

func TestEqualSum(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		SA, _ := crand.Int(crand.Reader, Q)
		SB, _ := crand.Int(crand.Reader, Q)

		A := MulByScalar(BASE, SA)
		B := MulByScalar(BASE, SB)

		AB := Add(A, B)

		if OnCurve(AB.X, AB.Y) == false {
			t.Errorf("Error in Add in Curve")
		}

		if OnCurve(A.X, A.Y) == false {
			t.Errorf("Error in A in Curve")
		}

		if OnCurve(B.X, B.Y) == false {
			t.Errorf("Error in B in Curve")
		}

		assert := test.NewAssert(t)

		assert.NoError(test.IsSolved(&CircuitEqualSum{}, &CircuitEqualSum{
			A:   PointToCircuit(A),
			B:   PointToCircuit(B),
			Sum: PointToCircuit(AB),
		}, ecc.BN254.ScalarField()))
	}
}

type CircuitInverse struct { // Test A * A^-1 = 1
	A    frontend.Variable
	InvA frontend.Variable
}

func (circuit *CircuitInverse) Define(api frontend.API) error {
	R := api.Mul(circuit.A, circuit.InvA)
	R = ModCircuit(R, api)
	api.AssertIsEqual(R, frontend.Variable(1))
	return nil
}

func TestInverse(t *testing.T) {
	A, _ := crand.Int(crand.Reader, Q)
	if A.Cmp(big.NewInt(0)) == 0 {
		A = big.NewInt(1)
	}
	InvA := big.NewInt(0).Exp(A, big.NewInt(0).Sub(Q, big.NewInt(2)), Q)
	if big.NewInt(0).Mod(big.NewInt(0).Mul(A, InvA), Q).Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Error in Big Int Inverse")
	}
	assert := test.NewAssert(t)
	assert.NoError(test.IsSolved(&CircuitInverse{}, &CircuitInverse{
		A:    frontend.Variable(A),
		InvA: frontend.Variable(InvA),
	}, ecc.BN254.ScalarField()))

}
