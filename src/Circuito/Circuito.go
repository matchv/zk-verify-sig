package Circuito

import (
	Curve "ed25519/src/CurveEd25519"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
)

const NVAL = 1

type Circuit struct {
	R   [NVAL]Curve.PointCircuit `gnark:",public"`
	S   [NVAL]Curve.Element      `gnark:",public"`
	A   [NVAL]Curve.PointCircuit `gnark:",public"`
	Msg [NVAL]Curve.Element      `gnark:",public"`
}

func Get(uapi *uints.BinaryField[uints.U64], X frontend.Variable) []uints.U8 {
	return uapi.UnpackMSB(uapi.ValueOf(X))
}

func HashToValue(uapi *uints.BinaryField[uints.U64], api frontend.API, hash []uints.U8) Curve.Element {
	res := Curve.StringToElement("0")
	api.Println("RES 0 : ", res.V[0], " ", res.V[1])
	for i := 0; i < len(hash); i++ {
		res = Curve.ProdElement(res, Curve.StringToElement("256"), api)
		res = Curve.AddElement(res, Curve.Element{[2]frontend.Variable{hash[i].Val, frontend.Variable(0)}}, api)
		api.Println("RES ", res.V[0], " ", res.V[1])
		//res = api.Mul(res, frontend.Variable(256))
		//res = api.Add(res, hash[i].Val)
	}
	return res
}

// 5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14

func (circuit *Circuit) Define(api frontend.API) error {

	api.Println("CURVE Q ", Curve.Q)
	for i := 0; i < NVAL; i++ {

		Curve.OnCurveCircuit(circuit.R[i], api)
		Curve.OnCurveCircuit(circuit.A[i], api)
		//curve.AssertIsOnCurve(circuit.R[i])
		//curve.AssertIsOnCurve(circuit.A[i])

		//api.AssertIsLessOrEqual(circuit.S[i], params.Order)
		//api.AssertIsDifferent(circuit.S[i], params.Order)
		B := Curve.GetBaseCircuit()

		sha512, _ := sha3.New512(api)
		uapi, _ := uints.New[uints.U64](api)

		sha512.Write(Curve.ElementToUint8(circuit.R[i].X, api, uapi))
		sha512.Write(Curve.ElementToUint8(circuit.R[i].Y, api, uapi))
		sha512.Write(Curve.ElementToUint8(circuit.A[i].X, api, uapi))
		sha512.Write(Curve.ElementToUint8(circuit.A[i].Y, api, uapi))
		sha512.Write(Curve.ElementToUint8(circuit.Msg[i], api, uapi))

		temp := sha512.Sum()
		for j := 0; j < len(temp); j++ {
			api.Println(temp[j].Val, " ")
		}
		k := HashToValue(uapi, api, temp) //uapi.ToValue(uapi.PackMSB(sha256.Sum()...))

		api.Println("K ", k.V[0], " ", k.V[1])

		B = Curve.MulByScalarCircuit(B, Curve.ProdElement(k, Curve.StringToElement("8"), api), api)
		//B = curve.ScalarMul(B, api.Mul(k, frontend.Variable(8)))

		A := Curve.AddCircuit(
			Curve.MulByScalarCircuit(circuit.R[i], Curve.StringToElement("8"), api),
			Curve.MulByScalarCircuit(circuit.A[i], Curve.ProdElement(k, Curve.StringToElement("8"), api), api), api)
		//A := curve.Add(curve.ScalarMul(circuit.R[i], frontend.Variable(8)),
		//	curve.ScalarMul(circuit.A[i], api.Mul(k, frontend.Variable(8))))

		Curve.AssertEqualElement(A.X, B.X, api)
		Curve.AssertEqualElement(A.Y, B.Y, api)
		//api.AssertIsEqual(A.X, B.X)
		//api.AssertIsEqual(A.Y, B.Y)
	}
	return nil
}
