package Circuito

import (
	Curve "ed25519/src/CurveEd25519"

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

// 5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14

func (circuit *Circuit) Define(api frontend.API) error {

	api.Println("CURVE Q ", Curve.Q)
	for i := 0; i < NVAL; i++ {
		curve, _ := twistededwards.NewEdCurve(api, tedwards.BN254)

		params := curve.Params()
		params.A.Set(Curve.A)
		params.D.Set(Curve.D)
		params.Cofactor.Set(Curve.Cofactor)
		params.Order.Set(Curve.Ord)
		params.Base[0].Set(Curve.BX)
		params.Base[1].Set(Curve.BY)

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
