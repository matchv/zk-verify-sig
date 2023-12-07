package curve_ed25519

import (
	//	"fmt"

	//	"github.com/consensys/gnark-crypto/ecc"
	//	"github.com/consensys/gnark-crypto/ecc/bn254"

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"
	//	"github.com/consensys/gnark/test"
	//"github.com/rs/zerolog"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"

	//	crand "crypto/rand"
	//	"testing"

	//	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	//	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	//	td "github.com/consensys/gnark/std/algebra/native/twistededwards"
	//	sha3 "golang.org/x/crypto/sha3"

	"math/big"

	"github.com/consensys/gnark/std/math/uints"
)

var Q *big.Int = new(big.Int)
var A *big.Int = new(big.Int)
var D *big.Int = new(big.Int)
var Ord *big.Int = new(big.Int)
var Cofactor *big.Int = new(big.Int)
var BX *big.Int = new(big.Int)
var BY *big.Int = new(big.Int)
var BU *big.Int = new(big.Int)
var BV *big.Int = new(big.Int)

type Point struct {
	X, Y *big.Int
}

// / Uses Little endian

func (p *Point) CompressForm() (res []byte) {
	res = make([]byte, 32)
	p.Y.FillBytes(res[:])
	if res[0]&0x80 == 0x80 {
		panic("Error")
	}
	if p.X.Bit(0) == 1 {
		res[0] |= 0x80
	}

	// Reverse the array
	for i := 0; i < 16; i++ {
		res[i], res[31-i] = res[31-i], res[i]
	}

	return
}

func (p *Point) CompressFormCircuit() (res []uints.U8) {
	res = make([]uints.U8, 32)
	temp := p.CompressForm()
	for i := 0; i < 32; i++ {
		res[i] = uints.NewU8(temp[i])
	}
	return
}

func CompressToPoint(b []byte) Point {
	var res Point
	tb := make([]byte, 32)
	copy(tb, b)
	tb[31] &= 0x7F
	for i := 0; i < 16; i++ {
		tb[i], tb[31-i] = tb[31-i], tb[i]
	}

	res.Y = new(big.Int).SetBytes(tb[:])
	num := big.NewInt(0).Exp(res.Y, big.NewInt(2), Q)
	num = big.NewInt(0).Sub(num, big.NewInt(1))
	num = big.NewInt(0).Add(num, Q)
	num = big.NewInt(0).Mod(num, Q)

	den := big.NewInt(0).Exp(res.Y, big.NewInt(2), Q)
	den = big.NewInt(0).Mul(den, D)
	den = big.NewInt(0).Add(den, big.NewInt(1))
	den = big.NewInt(0).Mod(den, Q)
	den = big.NewInt(0).ModInverse(den, Q)

	left := big.NewInt(0).Mul(num, den)
	left = big.NewInt(0).Mod(left, Q)

	res.X = big.NewInt(0).ModSqrt(left, Q)

	if res.X.Bit(0) != uint(b[31]&0x80)>>7 {
		res.X = big.NewInt(0).Sub(Q, res.X)
	}
	return res
}

func (p *Point) Bytes() []byte {
	return append(p.X.FillBytes(make([]byte, 32)), p.Y.FillBytes(make([]byte, 32))...)
}

func BytesToPoint(b []byte) Point {
	return Point{new(big.Int).SetBytes(b[:32]), new(big.Int).SetBytes(b[32:])}
}

var BASE Point

func BigMul(bs ...*big.Int) *big.Int {
	res := big.NewInt(1)
	for _, b := range bs {
		res = res.Mul(res, b)
	}
	return res
}

func BigAdd(bs ...*big.Int) *big.Int {
	res := big.NewInt(0)
	for _, b := range bs {
		res = res.Add(res, b)
	}
	return res
}

func Add(PA Point, PB Point) Point {
	var PC Point

	PC.X = big.NewInt(0).Mod(BigMul(BigAdd(BigMul(PA.X, PB.Y), BigMul(PA.Y, PB.X)),
		big.NewInt(0).Exp(
			BigAdd(big.NewInt(1), BigMul(D, PA.X, PB.X, PA.Y, PB.Y)),
			BigAdd(Q, big.NewInt(-2)), Q)), Q)

	PC.Y = big.NewInt(0).Mod(
		BigMul(
			BigAdd(BigMul(PA.Y, PB.Y), BigMul(big.NewInt(-1), A, PA.X, PB.X)),
			big.NewInt(0).Exp(BigAdd(big.NewInt(1),
				BigMul(big.NewInt(-1), D, PA.X, PA.Y, PB.X, PB.Y)),
				BigAdd(Q, big.NewInt(-2)), Q)), Q)
	return PC
}

func MulByScalar(P Point, SO *big.Int) Point {
	S := big.NewInt(0).Set(SO)
	res := Point{big.NewInt(0), big.NewInt(1)}
	for ; S.Cmp(big.NewInt(0)) > 0; S.Div(S, big.NewInt(2)) {
		if S.Bit(0) == 1 {
			res = Add(res, P)
		}
		P = Add(P, P)
	}
	return res
}

func OnCurve(X *big.Int, Y *big.Int) bool {
	//fmt.Println("On Curve")
	X2 := big.NewInt(0).Exp(X, big.NewInt(2), nil)
	Y2 := big.NewInt(0).Exp(Y, big.NewInt(2), nil)
	ladoIzq := big.NewInt(0).Add(big.NewInt(0).Mul(X2, big.NewInt(-1)), Y2)
	ladoDer := big.NewInt(0).Add(big.NewInt(1), big.NewInt(0).Mul(
		big.NewInt(0).Mul(D, X2), Y2))
	ladoIzq.Mod(ladoIzq, Q)
	ladoDer.Mod(ladoDer, Q)
	//fmt.Println(ladoIzq)
	//fmt.Println(ladoDer)

	return ladoIzq.Cmp(ladoDer) == 0
}
