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
		if big.NewInt(0).Mod(S, big.NewInt(2)).Cmp(big.NewInt(0)) == 1 {
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
