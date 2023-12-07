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
	"github.com/stretchr/testify/assert"

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
	AssertEqualElementQ(AB.X, circuit.Sum.X, api)
	AssertEqualElementQ(AB.Y, circuit.Sum.Y, api)
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
	S    ElementO     `gnark:",public"`
	Prod PointCircuit `gnark:",public"`
}

func (circuit *CircuitEqualProd) Define(api frontend.API) error {
	AB := MulByScalarCircuit(circuit.A, circuit.S, api)
	AssertEqualElementQ(AB.X, circuit.Prod.X, api)
	AssertEqualElementQ(AB.Y, circuit.Prod.Y, api)
	return nil
}

func TestEqualProd(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		A := BASE
		s, _ := crand.Int(crand.Reader, Ord)
		Prod := MulByScalar(A, s)
		if OnCurve(Prod.X, Prod.Y) == false {
			t.Errorf("Error in Prod in Curve")
		}
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(&CircuitEqualProd{}, &CircuitEqualProd{
			A:    PointToCircuit(A),
			S:    BigIntToElementO(s),
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
	X := HashToValueQ(uapi, api, circuit.UA[0:32])
	Y := HashToValueQ(uapi, api, circuit.UA[32:64])
	AssertEqualElementQ(X, circuit.A.X, api)
	AssertEqualElementQ(Y, circuit.A.Y, api)

	UX := ElementToUint8Q(circuit.A.X, api, uapi)
	UY := ElementToUint8Q(circuit.A.Y, api, uapi)
	for i := 0; i < 32; i++ {
		uapi.ByteAssertEq(UX[i], circuit.UA[i])
		uapi.ByteAssertEq(UY[i], circuit.UA[i+32])
	}

	return nil
}

func TestPointToBytes(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		s, _ := crand.Int(crand.Reader, Ord)
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

type CircuitCriticProduct struct {
	A   PointCircuit `gnark:",public"`
	R   PointCircuit `gnark:",public"`
	K   ElementO     `gnark:",public"`
	S   ElementO     `gnark:",public"`
	RES PointCircuit `gnark:",public"`
}

func (circuit *CircuitCriticProduct) Define(api frontend.API) error {
	A := MulByScalarCircuit(circuit.A, circuit.K, api)
	A = MulByScalarCircuit(A, StringToElementO("8"), api)
	R := MulByScalarCircuit(circuit.R, StringToElementO("8"), api)
	MyRes := AddCircuit(A, R, api)
	AssertEqualElementQ(MyRes.X, circuit.RES.X, api)

	B := GetBaseCircuit()
	B = MulByScalarCircuit(B, circuit.S, api)
	B = MulByScalarCircuit(B, StringToElementO("8"), api)

	AssertEqualElementQ(MyRes.X, B.X, api)
	AssertEqualElementQ(MyRes.Y, B.Y, api)

	return nil
}

func TestCriticProduct(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		s1, _ := crand.Int(crand.Reader, Q)
		s2, _ := crand.Int(crand.Reader, Q)
		A := MulByScalar(BASE, s1)
		R := MulByScalar(BASE, s2)
		k, _ := crand.Int(crand.Reader, Q)
		A2 := MulByScalar(A, k)
		A2 = MulByScalar(A2, big.NewInt(8))
		R2 := MulByScalar(R, big.NewInt(8))
		MyRes := Add(A2, R2)
		if OnCurve(MyRes.X, MyRes.Y) == false {
			t.Errorf("Error in Critic Product in Curve")
		}
		S := big.NewInt(0).Add(big.NewInt(0).Mul(k, s1), s2)
		S.Mod(S, Ord)
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(&CircuitCriticProduct{}, &CircuitCriticProduct{
			A:   PointToCircuit(A),
			R:   PointToCircuit(R),
			K:   BigIntToElementO(k),
			S:   BigIntToElementO(S),
			RES: PointToCircuit(MyRes),
		}, ecc.BN254.ScalarField()))
	}
}

type CircuitOnCurve struct {
	A PointCircuit `gnark:",public"`
}

func (circuit *CircuitOnCurve) Define(api frontend.API) error {
	OnCurveCircuit(circuit.A, api)
	return nil
}

func TestOnCurveCircuit(t *testing.T) {
	for nt := 0; nt < 100; nt++ {
		s, _ := crand.Int(crand.Reader, Ord)
		A := MulByScalar(BASE, s)
		assert.True(t, OnCurve(A.X, A.Y))
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(&CircuitOnCurve{}, &CircuitOnCurve{
			A: PointToCircuit(A),
		}, ecc.BN254.ScalarField()))
	}
}

type CircuitCompressForm struct {
	A  PointCircuit `gnark:",public"`
	CA [32]uints.U8 `gnark:",public"`
}

func (circuit *CircuitCompressForm) Define(api frontend.API) error {
	OnCurveCircuit(circuit.A, api)
	uapi, _ := uints.New[uints.U64](api)
	CA := CompressToPointCircuit(circuit.CA[:], api, uapi)
	AssertEqualElementQ(CA.X, circuit.A.X, api)
	AssertEqualElementQ(CA.Y, circuit.A.Y, api)
	return nil
}

func TestCompressFormCircuit(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		s, _ := crand.Int(crand.Reader, Ord)
		A := MulByScalar(BASE, s)
		fmt.Println(A)
		assert.True(t, OnCurve(A.X, A.Y))

		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(&CircuitCompressForm{}, &CircuitCompressForm{
			A:  PointToCircuit(A),
			CA: [32]uints.U8(A.CompressFormCircuit()),
		}, ecc.BN254.ScalarField()))
	}
}
