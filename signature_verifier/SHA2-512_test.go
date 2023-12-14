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
	Pre := make([]byte, 64)
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
	A, B, C, S, X, XS uints.U64
}

func (circuit *Uint64AddCircuitTest) Define(api frontend.API) error {
	uapi, _ := uints.New[uints.U64](api)
	s := Uint64AddCircuit(uapi, api, circuit.A, circuit.B, circuit.C)
	uapi.AssertEq(s, circuit.S)
	xs := uapi.Xor(s, circuit.X)
	uapi.AssertEq(xs, circuit.XS)
	xsx := uapi.Xor(xs, circuit.X)
	uapi.AssertEq(xsx, circuit.S)
	return nil
}

func TestUin64Add(t *testing.T) {
	ntest := 100
	for nv := 0; nv < ntest; nv++ {
		P1 := make([]byte, 8)
		P2 := make([]byte, 8)
		P3 := make([]byte, 8)
		PX := make([]byte, 8)
		crand.Read(P1[:])
		crand.Read(P2[:])
		crand.Read(P3[:])
		crand.Read(PX[:])
		P1[0] = 255
		P2[0] = 255
		A := big.NewInt(0).SetBytes(P1)
		B := big.NewInt(0).SetBytes(P2)
		C := big.NewInt(0).SetBytes(P3)
		S := big.NewInt(0).Add(A, B)
		S = S.Add(S, C)
		pow := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(64), nil)
		S = S.Mod(S, pow)
		X := big.NewInt(0).SetBytes(PX)
		SX := big.NewInt(0).Xor(S, X)
		circuit := new(Uint64AddCircuitTest)
		circuit.A = uints.NewU64(A.Uint64())
		circuit.B = uints.NewU64(B.Uint64())
		circuit.C = uints.NewU64(C.Uint64())
		circuit.S = uints.NewU64(S.Uint64())
		circuit.X = uints.NewU64(X.Uint64())
		circuit.XS = uints.NewU64(SX.Uint64())
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()))
	}
}

type CircuitConstants struct {
	H [8]uints.U64
	K [80]uints.U64
}

func (circuit *CircuitConstants) Define(api frontend.API) error {
	uapi, _ := uints.New[uints.U64](api)
	h, k := sha2_512_constants()
	for i := 0; i < 8; i++ {
		api.AssertIsEqual(uapi.ToValue(h[i]), uapi.ToValue(circuit.H[i]))
	}
	for i := 0; i < 80; i++ {
		api.AssertIsEqual(uapi.ToValue(k[i]), uapi.ToValue(circuit.K[i]))
	}
	return nil
}

func Constants() (h [8]uint64, k [80]uint64) {
	h = [8]uint64{0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179}

	k = [80]uint64{0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
		0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
		0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
		0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
		0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
		0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
		0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
		0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
		0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
		0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
		0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
		0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
		0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817}
	return
}

func TestConstants(t *testing.T) {
	h, k := Constants()
	circuit := new(CircuitConstants)
	for i := 0; i < 8; i++ {
		circuit.H[i] = uints.NewU64(h[i])
	}
	for i := 0; i < 80; i++ {
		circuit.K[i] = uints.NewU64(k[i])
	}
	assert := test.NewAssert(t)
	assert.NoError(test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()))
}

type BlockCircuit struct {
	H0     [8]uints.U64  `gnark:",public"`
	K      [80]uints.U64 `gnark:",public"`
	Input8 [128]uints.U8 `gnark:",public"`
	H1     [8]uints.U64  `gnark:",public"`
}

func (circuit *BlockCircuit) Define(api frontend.API) error {
	uapi, _ := uints.New[uints.U64](api)
	h0 := circuit.H0
	k := circuit.K
	input8 := circuit.Input8
	h1 := circuit.H1
	myh1 := SHA2_512_block(uapi, api, h0, input8, k)
	fmt.Println(h1)
	fmt.Println(myh1)
	for i := 0; i < 8; i++ {
		uapi.AssertEq(myh1[i], h1[i])
	}
	return nil
}

func rotateRight(x uint64, k uint) uint64 {
	return (x >> k) | (x << (64 - k))
}

func sha2_512_block(h [8]uint64, input [128]byte, k [80]uint64) (h1 [8]uint64) {
	var w [80]uint64
	for i := 0; i < 16; i++ {
		w[i] = uint64(input[8*i+0])<<56 | uint64(input[8*i+1])<<48 | uint64(input[8*i+2])<<40 | uint64(input[8*i+3])<<32 | uint64(input[8*i+4])<<24 | uint64(input[8*i+5])<<16 | uint64(input[8*i+6])<<8 | uint64(input[8*i+7])
	}
	for i := 16; i < 80; i++ {
		s0 := uint64(rotateRight(w[i-15], 1) ^ rotateRight(w[i-15], 8) ^ (w[i-15] >> 7))
		s1 := uint64(rotateRight(w[i-2], 19) ^ rotateRight(w[i-2], 61) ^ (w[i-2] >> 6))
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}
	a, b, c, d, e, f, g, hh := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
	for i := 0; i < 80; i++ {
		s0 := uint64(rotateRight(a, 28) ^ rotateRight(a, 34) ^ rotateRight(a, 39))
		maj := uint64((a & b) ^ (a & c) ^ (b & c))
		t2 := s0 + maj
		s1 := uint64(rotateRight(e, 14) ^ rotateRight(e, 18) ^ rotateRight(e, 41))
		ch := uint64((e & f) ^ ((^e) & g))
		t1 := hh + s1 + ch + k[i] + w[i]
		hh, g, f, e, d, c, b, a = g, f, e, d+t1, c, b, a, t1+t2
	}
	h1[0] = a + h[0]
	h1[1] = b + h[1]
	h1[2] = c + h[2]
	h1[3] = d + h[3]
	h1[4] = e + h[4]
	h1[5] = f + h[5]
	h1[6] = g + h[6]
	h1[7] = hh + h[7]
	return
}
func TestBlock(t *testing.T) {
	a := uint64(1)
	fmt.Println(a, " ", ^a)
	h, k := Constants()
	circuit := new(BlockCircuit)
	input8 := make([]byte, 128)
	crand.Read(input8[:])
	h1 := sha2_512_block(h, [128]byte(input8), k)
	for i := 0; i < 8; i++ {
		circuit.H0[i] = uints.NewU64(h[i])
		circuit.H1[i] = uints.NewU64(h1[i])
	}
	for i := 0; i < 80; i++ {
		circuit.K[i] = uints.NewU64(k[i])
	}
	for i := 0; i < 128; i++ {
		circuit.Input8[i] = uints.NewU8(input8[i])
	}

	assert := test.NewAssert(t)
	assert.NoError(test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()))
}
