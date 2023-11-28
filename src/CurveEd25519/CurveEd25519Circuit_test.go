package Curve

import (

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"

	//"github.com/rs/zerolog"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"
	crand "crypto/rand"
	"testing"

	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
	"github.com/consensys/gnark/std/math/uints"
)

type CircuitEqualSum struct { // Test A + B = Sum
	A   PointCircuit `gnark:",public"`
	B   PointCircuit `gnark:",public"`
	Sum PointCircuit `gnark:",public"`
}

func (circuit *CircuitEqualSum) Define(api frontend.API) error {
	AB := AddCircuit(circuit.A, circuit.B, api)
	AssertEqualElement(AB.X, circuit.Sum.X, api)
	AssertEqualElement(AB.Y, circuit.Sum.Y, api)
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

type CircuitEqualProd struct { // Test A * B = Prod
	A    PointCircuit `gnark:",public"`
	S    Element      `gnark:",public"`
	Prod PointCircuit `gnark:",public"`
}

func (circuit *CircuitEqualProd) Define(api frontend.API) error {
	AB := MulByScalarCircuit(circuit.A, circuit.S, api)
	AssertEqualElement(AB.X, circuit.Prod.X, api)
	AssertEqualElement(AB.Y, circuit.Prod.Y, api)
	return nil
}

func TestEqualProd(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		A := BASE
		s, _ := crand.Int(crand.Reader, Q)
		Prod := MulByScalar(A, s)
		if OnCurve(Prod.X, Prod.Y) == false {
			t.Errorf("Error in Prod in Curve")
		}
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(&CircuitEqualProd{}, &CircuitEqualProd{
			A:    PointToCircuit(A),
			S:    BigIntToElement(s),
			Prod: PointToCircuit(Prod),
		}, ecc.BN254.ScalarField()))
	}
}

type CircuitPointToBytes struct { // Test PointToBytes
	A  PointCircuit `gnark:",public"`
	UA [64]uints.U8 `gnark:",public"`
}

func (circuit *CircuitPointToBytes) Define(api frontend.API) error {
	uapi, _ := uints.New[uints.U64](api)
	X := HashToValue(uapi, api, circuit.UA[0:32])
	Y := HashToValue(uapi, api, circuit.UA[32:64])
	AssertEqualElement(X, circuit.A.X, api)
	AssertEqualElement(Y, circuit.A.Y, api)

	UX := ElementToUint8(circuit.A.X, api, uapi)
	UY := ElementToUint8(circuit.A.Y, api, uapi)
	for i := 0; i < 32; i++ {
		uapi.ByteAssertEq(UX[i], circuit.UA[i])
		uapi.ByteAssertEq(UY[i], circuit.UA[i+32])
	}

	return nil
}

func TestPointToBytes(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		s, _ := crand.Int(crand.Reader, Q)
		A := IntToPoint(s)
		bX := A.X.FillBytes(make([]byte, 32))
		bY := A.Y.FillBytes(make([]byte, 32))

		tA := PointToCircuit(A)
		var tUA [64]uints.U8
		for i := 0; i < 32; i++ {
			tUA[i] = uints.NewU8(bX[i])
			tUA[i+32] = uints.NewU8(bY[i])
		}
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(&CircuitPointToBytes{}, &CircuitPointToBytes{
			A:  tA,
			UA: tUA,
		}, ecc.BN254.ScalarField()))
	}
}
