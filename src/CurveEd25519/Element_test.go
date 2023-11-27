package Curve

import (

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"

	//"github.com/rs/zerolog"

	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"
	crand "crypto/rand"
	"testing"

	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
	"github.com/consensys/gnark/std/hash/sha3"
	csha3 "golang.org/x/crypto/sha3"
)

type CircuitOne struct {
	One Element
}

func (circuit *CircuitOne) Define(api frontend.API) error {
	api.AssertIsEqual(circuit.One.V[0], frontend.Variable(big.NewInt(1)))
	api.AssertIsEqual(circuit.One.V[1], frontend.Variable(big.NewInt(0)))
	return nil
}

func TestOneElement(t *testing.T) {
	assert := test.NewAssert(t)
	assert.NoError(test.IsSolved(&CircuitOne{}, &CircuitOne{
		One: BigIntToElement(big.NewInt(1)),
	}, ecc.BN254.ScalarField()))
}

type CircuitInverse struct { // Test A * A^-1 = 1
	A    Element
	InvA Element
}

func (circuit *CircuitInverse) Define(api frontend.API) error {
	R := ProdElement(circuit.A, circuit.InvA, api)
	One := BigIntToElement(big.NewInt(1))
	AssertEqualElement(R, One, api)
	return nil
}

func TestInverseElement(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
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
			A:    BigIntToElement(A),
			InvA: BigIntToElement(InvA),
		}, ecc.BN254.ScalarField()))
	}

	for nt := 0; nt < 10; nt++ {
		A, _ := crand.Int(crand.Reader, Q)
		B, _ := crand.Int(crand.Reader, Q)
		fmt.Println(A)
		fmt.Println(B)
		assert := test.NewAssert(t)
		assert.Error(test.IsSolved(&CircuitInverse{}, &CircuitInverse{
			A:    BigIntToElement(A),
			InvA: BigIntToElement(B),
		}, ecc.BN254.ScalarField()))
	}
}

type CircuitAdd struct {
	A   Element
	B   Element
	Sum Element
}

func (circuit *CircuitAdd) Define(api frontend.API) error {
	C := AddElement(circuit.A, circuit.B, api)
	AssertEqualElement(C, circuit.Sum, api)
	return nil
}

func TestAddElement(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		A, _ := crand.Int(crand.Reader, Q)
		B, _ := crand.Int(crand.Reader, Q)
		C := big.NewInt(0).Add(A, B)
		C = C.Mod(C, Q)
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(&CircuitAdd{}, &CircuitAdd{
			A:   BigIntToElement(A),
			B:   BigIntToElement(B),
			Sum: BigIntToElement(C),
		}, ecc.BN254.ScalarField()))
	}
	for nt := 0; nt < 10; nt++ {
		A, _ := crand.Int(crand.Reader, Q)
		B, _ := crand.Int(crand.Reader, Q)
		C := big.NewInt(0).Add(A, B)
		C = C.Mod(C, Q)
		assert := test.NewAssert(t)
		assert.Error(test.IsSolved(&CircuitAdd{}, &CircuitAdd{
			A:   BigIntToElement(A),
			B:   BigIntToElement(B),
			Sum: BigIntToElement(big.NewInt(0).Add(C, big.NewInt(1))),
		}, ecc.BN254.ScalarField()))
	}

}

type CircuitProd struct {
	A    Element
	B    Element
	Prod Element
}

func (circuit *CircuitProd) Define(api frontend.API) error {
	C := ProdElement(circuit.A, circuit.B, api)
	AssertEqualElement(C, circuit.Prod, api)
	return nil
}

func TestProdElement(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		A, _ := crand.Int(crand.Reader, Q)
		B, _ := crand.Int(crand.Reader, Q)
		C := big.NewInt(0).Mul(A, B)
		C = C.Mod(C, Q)
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(&CircuitProd{}, &CircuitProd{
			A:    BigIntToElement(A),
			B:    BigIntToElement(B),
			Prod: BigIntToElement(C),
		}, ecc.BN254.ScalarField()))
	}

	for nt := 0; nt < 10; nt++ {
		A, _ := crand.Int(crand.Reader, Q)
		B, _ := crand.Int(crand.Reader, Q)
		C := big.NewInt(0).Mul(A, B)
		C = C.Mod(C, Q)
		assert := test.NewAssert(t)
		assert.Error(test.IsSolved(&CircuitProd{}, &CircuitProd{
			A:    BigIntToElement(A),
			B:    BigIntToElement(B),
			Prod: BigIntToElement(big.NewInt(0).Add(C, big.NewInt(1))),
		}, ecc.BN254.ScalarField()))
	}
}

type CircuitBits struct {
	A    Element
	Bits [256]frontend.Variable
}

func (circuit *CircuitBits) Define(api frontend.API) error {
	Bits := BitsElement(circuit.A, api)
	for i := 0; i < 256; i++ {
		api.Println("BIT ", i, " ", circuit.Bits[i], " vs ", Bits[i])
		api.AssertIsEqual(Bits[i], circuit.Bits[i])
	}
	return nil
}

func TestBitsElement(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		A, _ := crand.Int(crand.Reader, Q)
		A0 := big.NewInt(0).Set(A)
		fmt.Println(A0)
		var Bits [256]frontend.Variable
		for i := 0; i < 256; i++ {
			Bits[i] = frontend.Variable(big.NewInt(0).Mod(A, big.NewInt(2)))
			A = big.NewInt(0).Div(A, big.NewInt(2))
		}
		//fmt.Println(A)
		//fmt.Println(A0)
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(&CircuitBits{}, &CircuitBits{
			A:    BigIntToElement(A0),
			Bits: Bits,
		}, ecc.BN254.ScalarField()))
	}
}

type CircuitToU8 struct {
	A   Element
	AU8 [32]uints.U8
}

func (circuit *CircuitToU8) Define(api frontend.API) error {
	uapi, _ := uints.New[uints.U64](api)
	locU8 := ElementToUint8(circuit.A, api, uapi)
	for i := 0; i < 32; i++ {
		//api.Println("U8 ", i, " ", circuit.AU8[i], " vs ", locU8[i])
		api.AssertIsEqual(locU8[i].Val, circuit.AU8[i].Val)
	}
	return nil
}

func TestToU8Element(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		A, _ := crand.Int(crand.Reader, Q)
		A0 := big.NewInt(0).Set(A)
		var AU8 [32]uints.U8
		for i := 0; i < 32; i++ {
			AU8[i].Val = frontend.Variable(big.NewInt(0).Mod(A, big.NewInt(256)))
			A = big.NewInt(0).Div(A, big.NewInt(256))
		}
		//fmt.Println(A)
		//fmt.Println(A0)
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(&CircuitToU8{}, &CircuitToU8{
			A:   BigIntToElement(A0),
			AU8: AU8,
		}, ecc.BN254.ScalarField()))
	}
}

type CircuitSHA512 struct {
	A    Element
	Hash [64]uints.U8
}

func (circuit *CircuitSHA512) Define(api frontend.API) error {
	sha512, _ := sha3.New512(api)
	uapi, _ := uints.New[uints.U64](api)
	sha512.Write(ElementToUint8(circuit.A, api, uapi))
	temp := ElementToUint8(circuit.A, api, uapi)
	for i := 0; i < len(temp); i++ {
		api.Println(temp[i].Val, " ")
	}
	locHash := sha512.Sum()
	api.Println(len(circuit.Hash))
	api.Println(len(locHash))
	for i := 0; i < len(locHash); i++ {
		api.Println("U8 ", i, " ", circuit.Hash[i].Val, " vs ", locHash[i].Val)
	}
	for i := 0; i < len(locHash); i++ {
		uapi.ByteAssertEq(locHash[i], circuit.Hash[i])
	}
	return nil
}

func TestSHA512Element(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		A, _ := crand.Int(crand.Reader, Q)
		A0 := big.NewInt(0).Set(A)
		sha512 := csha3.New512()
		fmt.Println(A.FillBytes(make([]byte, 32)))
		sha512.Write(A.FillBytes(make([]byte, 32)))
		locHash := sha512.Sum(nil)
		//fmt.Println(locHash)
		//fmt.Println(len(locHash))
		//fmt.Println(A)
		//fmt.Println(A0)
		assert := test.NewAssert(t)
		var Hash [64]uints.U8
		for i := 0; i < len(locHash); i++ {
			Hash[i] = uints.NewU8(locHash[i])
		}
		//fmt.Println(len(Hash))
		assert.NoError(test.IsSolved(&CircuitSHA512{}, &CircuitSHA512{
			A:    BigIntToElement(A0),
			Hash: Hash,
		}, ecc.BN254.ScalarField()))
	}
}
