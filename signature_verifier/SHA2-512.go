package signature_verifier

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	//csha3 "golang.org/x/crypto/sha2"
)

// / len(input) <= 895

func SHA2_512Circuit(uapi *uints.BinaryField[uints.U64], api frontend.API, input []uints.U8) [64]uints.U8 {
	n := len(input)
	L := n * 8
	fmt.Println("n = ", n)
	input8 := make([]uints.U8, 128)
	copy(input8, input)
	input8[n] = uints.NewU8(0x80)
	for i := 127; i >= 112; i-- {
		input8[i] = uints.NewU8(uint8(L % 256))
		L = L / 256
	}
	for i := n + 1; i < 122; i++ {
		input8[i] = uints.NewU8(0)
	}
	input64 := ArrayU8toU64Circuit(uapi, input8)
	h, k := sha2_512_constants()
	//api.Println(len(input64))
	//fmt.Println(input64)
	var w [80]uints.U64
	copy(w[:16], input64)
	for i := len(input64); i < 80; i++ {
		w[i] = uints.NewU64(0)
	}
	for i := 16; i < 80; i++ {
		s01 := uapi.Lrot(w[i-15], -1)
		s02 := uapi.Lrot(w[i-15], -8)
		s03 := uapi.Rshift(w[i-15], 7)
		s0 := uapi.Xor(s01, s02, s03)

		s11 := uapi.Lrot(w[i-2], -19)
		s12 := uapi.Lrot(w[i-2], -3)
		s13 := uapi.Rshift(w[i-2], 6)
		s1 := uapi.Xor(s11, s12, s13)

		w[i] = Uint64AddCircuit(uapi, api, w[i-16], s0, w[i-7], s1)
	}

	a, b, c, d, e, f, g, hh := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]

	for i := 0; i < 80; i++ {
		S01 := uapi.Lrot(a, -28)
		S02 := uapi.Lrot(a, -34)
		S03 := uapi.Lrot(a, -29)
		S0 := uapi.Xor(S01, S02, S03)

		S11 := uapi.Lrot(e, -14)
		S12 := uapi.Lrot(e, -18)
		S13 := uapi.Lrot(e, -41)
		S1 := uapi.Xor(S11, S12, S13)

		ch := uapi.Xor(uapi.And(e, f), uapi.And(uapi.Not(e), g))
		temp1 := Uint64AddCircuit(uapi, api, hh, S1, ch, k[i], w[i])

		maj := uapi.Xor(uapi.And(a, b), uapi.And(a, c), uapi.And(b, c))
		temp2 := Uint64AddCircuit(uapi, api, S0, maj)

		hh = g
		g = f
		f = e
		e = Uint64AddCircuit(uapi, api, d, temp1)
		d = c
		c = b
		b = a
		a = Uint64AddCircuit(uapi, api, temp1, temp2)
	}

	h[0] = Uint64AddCircuit(uapi, api, h[0], a)
	h[1] = Uint64AddCircuit(uapi, api, h[1], b)
	h[2] = Uint64AddCircuit(uapi, api, h[2], c)
	h[3] = Uint64AddCircuit(uapi, api, h[3], d)
	h[4] = Uint64AddCircuit(uapi, api, h[4], e)
	h[5] = Uint64AddCircuit(uapi, api, h[5], f)
	h[6] = Uint64AddCircuit(uapi, api, h[6], g)
	h[7] = Uint64AddCircuit(uapi, api, h[7], hh)

	res := make([]uints.U8, 0, 64)
	for i := 0; i < 8; i++ {
		res = append(res, uapi.UnpackLSB(h[i])...)
	}
	return [64]uints.U8(res)
}

func HintDivMod64bits(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	a := inputs[0]
	pow := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(64), nil)
	result[0], result[1] = big.NewInt(0).DivMod(a, pow, big.NewInt(0))
	return nil
}

func Uint64AddCircuit(uapi *uints.BinaryField[uints.U64], api frontend.API, a ...uints.U64) uints.U64 {
	va := make([]frontend.Variable, len(a))
	for i := range a {
		va[i] = uapi.ToValue(a[i])
	}
	vres := api.Add(va[0], va[1], va[2:]...)
	ret, _ := api.Compiler().NewHint(HintDivMod64bits, 2, vres)
	c, r := ret[0], ret[1]
	pow := frontend.Variable(big.NewInt(0).Exp(big.NewInt(2), big.NewInt(64), nil))
	api.AssertIsEqual(vres, api.Add(r, api.Mul(c, pow)))
	return uapi.ValueOf(r)
}

func sha2_512_constants() ([8]uints.U64, [80]uints.U64) {
	h := [8]uints.U64{
		uints.NewU64(0x6a09e667f3bcc908),
		uints.NewU64(0xbb67ae8584caa73b),
		uints.NewU64(0x3c6ef372fe94f82b),
		uints.NewU64(0xa54ff53a5f1d36f1),
		uints.NewU64(0x510e527fade682d1),
		uints.NewU64(0x9b05688c2b3e6c1f),
		uints.NewU64(0x1f83d9abfb41bd6b),
		uints.NewU64(0x5be0cd19137e2179)}

	k := [80]uints.U64{
		uints.NewU64(0x428a2f98d728ae22),
		uints.NewU64(0x7137449123ef65cd),
		uints.NewU64(0xb5c0fbcfec4d3b2f),
		uints.NewU64(0xe9b5dba58189dbbc),
		uints.NewU64(0x3956c25bf348b538),
		uints.NewU64(0x59f111f1b605d019),
		uints.NewU64(0x923f82a4af194f9b),
		uints.NewU64(0xab1c5ed5da6d8118),
		uints.NewU64(0xd807aa98a3030242),
		uints.NewU64(0x12835b0145706fbe),
		uints.NewU64(0x243185be4ee4b28c),
		uints.NewU64(0x550c7dc3d5ffb4e2),
		uints.NewU64(0x72be5d74f27b896f),
		uints.NewU64(0x80deb1fe3b1696b1),
		uints.NewU64(0x9bdc06a725c71235),
		uints.NewU64(0xc19bf174cf692694),
		uints.NewU64(0xe49b69c19ef14ad2),
		uints.NewU64(0xefbe4786384f25e3),
		uints.NewU64(0x0fc19dc68b8cd5b5),
		uints.NewU64(0x240ca1cc77ac9c65),
		uints.NewU64(0x2de92c6f592b0275),
		uints.NewU64(0x4a7484aa6ea6e483),
		uints.NewU64(0x5cb0a9dcbd41fbd4),
		uints.NewU64(0x76f988da831153b5),
		uints.NewU64(0x983e5152ee66dfab),
		uints.NewU64(0xa831c66d2db43210),
		uints.NewU64(0xb00327c898fb213f),
		uints.NewU64(0xbf597fc7beef0ee4),
		uints.NewU64(0xc6e00bf33da88fc2),
		uints.NewU64(0xd5a79147930aa725),
		uints.NewU64(0x06ca6351e003826f),
		uints.NewU64(0x142929670a0e6e70),
		uints.NewU64(0x27b70a8546d22ffc),
		uints.NewU64(0x2e1b21385c26c926),
		uints.NewU64(0x4d2c6dfc5ac42aed),
		uints.NewU64(0x53380d139d95b3df),
		uints.NewU64(0x650a73548baf63de),
		uints.NewU64(0x766a0abb3c77b2a8),
		uints.NewU64(0x81c2c92e47edaee6),
		uints.NewU64(0x92722c851482353b),
		uints.NewU64(0xa2bfe8a14cf10364),
		uints.NewU64(0xa81a664bbc423001),
		uints.NewU64(0xc24b8b70d0f89791),
		uints.NewU64(0xc76c51a30654be30),
		uints.NewU64(0xd192e819d6ef5218),
		uints.NewU64(0xd69906245565a910),
		uints.NewU64(0xf40e35855771202a),
		uints.NewU64(0x106aa07032bbd1b8),
		uints.NewU64(0x19a4c116b8d2d0c8),
		uints.NewU64(0x1e376c085141ab53),
		uints.NewU64(0x2748774cdf8eeb99),
		uints.NewU64(0x34b0bcb5e19b48a8),
		uints.NewU64(0x391c0cb3c5c95a63),
		uints.NewU64(0x4ed8aa4ae3418acb),
		uints.NewU64(0x5b9cca4f7763e373),
		uints.NewU64(0x682e6ff3d6b2b8a3),
		uints.NewU64(0x748f82ee5defb2fc),
		uints.NewU64(0x78a5636f43172f60),
		uints.NewU64(0x84c87814a1f0ab72),
		uints.NewU64(0x8cc702081a6439ec),
		uints.NewU64(0x90befffa23631e28),
		uints.NewU64(0xa4506cebde82bde9),
		uints.NewU64(0xbef9a3f7b2c67915),
		uints.NewU64(0xc67178f2e372532b),
		uints.NewU64(0xca273eceea26619c),
		uints.NewU64(0xd186b8c721c0c207),
		uints.NewU64(0xeada7dd6cde0eb1e),
		uints.NewU64(0xf57d4f7fee6ed178),
		uints.NewU64(0x06f067aa72176fba),
		uints.NewU64(0x0a637dc5a2c898a6),
		uints.NewU64(0x113f9804bef90dae),
		uints.NewU64(0x1b710b35131c471b),
		uints.NewU64(0x28db77f523047d84),
		uints.NewU64(0x32caab7b40c72493),
		uints.NewU64(0x3c9ebe0a15c9bebc),
		uints.NewU64(0x431d67c49c100d4c),
		uints.NewU64(0x4cc5d4becb3e42b6),
		uints.NewU64(0x597f299cfc657e2a),
		uints.NewU64(0x5fcb6fab3ad6faec),
		uints.NewU64(0x6c44198c4a475817)}
	return h, k
}
