package Circuito

import (
	"fmt"
	"math/big"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
)

const NVAL = 8

type Circuit struct {
	R   [NVAL]twistededwards.Point `gnark:",public"`
	S   [NVAL]frontend.Variable    `gnark:",public"`
	A   [NVAL]twistededwards.Point `gnark:",public"`
	Msg [NVAL]frontend.Variable    `gnark:",public"`
}

func Get(uapi *uints.BinaryField[uints.U64], X frontend.Variable) []uints.U8 {
	return uapi.UnpackMSB(uapi.ValueOf(X))
}

func HashToValue(uapi *uints.BinaryField[uints.U64], api frontend.API, hash []uints.U8) frontend.Variable {
	res := frontend.Variable(0)
	for i := 0; i < len(hash); i++ {
		res = api.Mul(res, frontend.Variable(256))
		res = api.Add(res, hash[i].Val)
	}
	return res
}

var q *big.Int = new(big.Int)
var a *big.Int = new(big.Int)
var d *big.Int = new(big.Int)
var ord *big.Int = new(big.Int)
var cofactor *big.Int = new(big.Int)
var bX *big.Int = new(big.Int)
var bY *big.Int = new(big.Int)
var bu *big.Int = new(big.Int)
var bv *big.Int = new(big.Int)

func OnCurve(X *big.Int, Y *big.Int) bool {
	//fmt.Println("On Curve")
	X2 := big.NewInt(0).Exp(X, big.NewInt(2), nil)
	Y2 := big.NewInt(0).Exp(Y, big.NewInt(2), nil)
	ladoIzq := big.NewInt(0).Add(big.NewInt(0).Mul(X2, a), Y2)
	ladoDer := big.NewInt(0).Add(big.NewInt(1), big.NewInt(0).Mul(
		big.NewInt(0).Mul(d, X2), Y2))
	return ladoIzq.Cmp(ladoDer) == 0
}

// 5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14
func init() {
	fmt.Println("Iniciando...")
	var temp *big.Int = new(big.Int)
	q.Exp(big.NewInt(2), big.NewInt(255), nil)
	q.Sub(q, big.NewInt(19))

	a.SetUint64(486664)
	d.SetUint64(486660)
	temp.SetString("27742317777372353535851937790883648493", 10)
	ord.Exp(big.NewInt(2), big.NewInt(252), nil)
	ord.Add(ord, temp)

	bu.Set(big.NewInt(9))
	bv.SetString("5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14", 16)

	bX.Mul(bu, big.NewInt(0).ModInverse(bv, q))
	bY.Mul(big.NewInt(1).Add(big.NewInt(-1), bu),
		big.NewInt(0).ModInverse(big.NewInt(0).Add(big.NewInt(1), bu), q))

	bX.Mod(bX, q)
	bY.Mod(bY, q)
}

func (circuit *Circuit) Define(api frontend.API) error {

	for i := 0; i < NVAL; i++ {
		curve, _ := twistededwards.NewEdCurve(api, tedwards.BN254)

		params := curve.Params()
		params.A.Set(a)
		params.D.Set(d)
		params.Cofactor.Set(cofactor)
		params.Order.Set(ord)
		params.Base[0].Set(bX)
		params.Base[1].Set(bY)

		curve.AssertIsOnCurve(circuit.R[i])
		curve.AssertIsOnCurve(circuit.A[i])

		api.AssertIsLessOrEqual(circuit.S[i], params.Order)
		api.AssertIsDifferent(circuit.S[i], params.Order)
		var B twistededwards.Point
		B.X = params.Base[0]
		B.Y = params.Base[1]

		sha512, _ := sha3.New512(api)
		uapi, _ := uints.New[uints.U64](api)

		sha512.Write(Get(uapi, circuit.R[i].X))
		sha512.Write(Get(uapi, circuit.R[i].Y))
		sha512.Write(Get(uapi, circuit.A[i].X))
		sha512.Write(Get(uapi, circuit.A[i].Y))
		sha512.Write(Get(uapi, circuit.Msg[i]))
		k := HashToValue(uapi, api, sha512.Sum()) //uapi.ToValue(uapi.PackMSB(sha256.Sum()...))

		B = curve.ScalarMul(B, api.Mul(k, frontend.Variable(8)))

		A := curve.Add(curve.ScalarMul(circuit.R[i], frontend.Variable(8)),
			curve.ScalarMul(circuit.A[i], api.Mul(k, frontend.Variable(8))))

		api.AssertIsEqual(A.X, B.X)
		api.AssertIsEqual(A.Y, B.Y)
	}
	return nil
}
