package signature_verifier

import (
	crand "crypto/rand"
	csha2 "crypto/sha512"
	"ed25519/curve_ed25519"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	//"github.com/rs/zerolog"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"

	"testing"
	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
)

type CircuitSHA512 struct {
	K   curve_ed25519.ElementO `gnark:",public"`
	Pre [64]uints.U8
}

func (circuit *CircuitSHA512) Define(api frontend.API) error {
	uapi, _ := uints.New[uints.U64](api)
	hashk := SHA2_512Circuit(uapi, api, circuit.Pre[:])
	api.Println("casa ")
	for i := 0; i < 64; i++ {
		api.Println(hashk[i].Val)
	}
	k := curve_ed25519.HashToValueO(api, hashk[:])
	api.Println(k.V[0], " vs ", circuit.K.V[0])
	api.Println(k.V[1], " vs ", circuit.K.V[1])
	curve_ed25519.AssertEqualElementO(k, circuit.K, api)
	return nil
}

func TestSHA2_512_Circuit(t *testing.T) {
	for nv := 0; nv < 300; nv++ {
		circuit := new(CircuitSHA512)
		Pre := make([]byte, 64)
		crand.Read(Pre[:])
		sha512 := csha2.New()
		fmt.Println(Pre)
		sha512.Write(Pre[:])
		temp := InvertArray(sha512.Sum(nil))
		fmt.Println(temp)
		K := big.NewInt(0).SetBytes(temp)
		K.Mod(K, curve_ed25519.Ord)
		circuit.K = curve_ed25519.BigIntToElementO(K)
		fmt.Println(K)
		for i := 0; i < 64; i++ {
			circuit.Pre[i] = uints.NewU8(Pre[i])
		}
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()))
	}
}

func TestSHA2_512_Circuit2(t *testing.T) {
	circuit := new(CircuitSHA512)
	Pre := make([]byte, 1)
	Pre[0] = 0

	sha512 := csha2.New()
	fmt.Println(Pre)
	sha512.Write(Pre[:])
	temp := InvertArray(sha512.Sum(nil))
	fmt.Println(temp)
	K := big.NewInt(0).SetBytes(temp)
	K.Mod(K, curve_ed25519.Ord)
	circuit.K = curve_ed25519.BigIntToElementO(K)
	fmt.Println(K)
	for i := 0; i < len(Pre); i++ {
		circuit.Pre[i] = uints.NewU8(Pre[i])
	}
	assert := test.NewAssert(t)
	assert.NoError(test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()))
}

type Uint64AddCircuitTest struct {
	A, B, C uints.U64
}

func (circuit *Uint64AddCircuitTest) Define(api frontend.API) error {
	uapi, _ := uints.New[uints.U64](api)
	c := Uint64AddCircuit(uapi, api, circuit.A, circuit.B)
	VC := uapi.ToValue(circuit.C)
	vc := uapi.ToValue(c)
	api.AssertIsEqual(vc, VC)
	return nil
}

func TestUin64Add(t *testing.T) {
	ntest := 100
	for nv := 0; nv < ntest; nv++ {
		P1 := make([]byte, 8)
		P2 := make([]byte, 8)
		crand.Read(P1[:])
		crand.Read(P2[:])
		A := big.NewInt(0).SetBytes(P1)
		B := big.NewInt(0).SetBytes(P2)
		C := big.NewInt(0).Add(A, B)
		C = C.Mod(C, big.NewInt(0).Exp(big.NewInt(2), big.NewInt(64), nil))
		circuit := new(Uint64AddCircuitTest)
		circuit.A = uints.NewU64(A.Uint64())
		circuit.B = uints.NewU64(B.Uint64())
		circuit.C = uints.NewU64(C.Uint64())
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()))
	}
}
