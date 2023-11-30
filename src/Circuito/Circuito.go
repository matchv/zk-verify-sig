package Circuito

import (
	Curve "ed25519/src/CurveEd25519"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
)

const NVAL = 1
const MLAR = 16 /// d(nbConstrains)/d(MLAR) aprox 5.000

type Circuit struct {
	R   [NVAL]Curve.PointCircuit `gnark:",public"`
	S   [NVAL]Curve.ElementO     `gnark:",public"`
	A   [NVAL]Curve.PointCircuit `gnark:",public"`
	Msg [NVAL][MLAR]uints.U8     `gnark:",public"`
	//Msg [NVAL]Curve.ElementF     `gnark:",public"`
}

func Get(uapi *uints.BinaryField[uints.U64], X frontend.Variable) []uints.U8 {
	return uapi.UnpackMSB(uapi.ValueOf(X))
}

// 5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14

func (circuit *Circuit) Define(api frontend.API) error {

	//	api.Println("CURVE Q ", Curve.Q)
	for i := 0; i < NVAL; i++ {

		Curve.OnCurveCircuit(circuit.R[i], api)
		Curve.OnCurveCircuit(circuit.A[i], api)
		//curve.AssertIsOnCurve(circuit.R[i])
		//curve.AssertIsOnCurve(circuit.A[i])

		//api.AssertIsLessOrEqual(circuit.S[i], params.Order)
		//api.AssertIsDifferent(circuit.S[i], params.Order)

		sha512, _ := sha3.New512(api)
		uapi, _ := uints.New[uints.U64](api)

		sha512.Write(Curve.ElementToUint8Q(circuit.R[i].X, api, uapi))
		sha512.Write(Curve.ElementToUint8Q(circuit.R[i].Y, api, uapi))
		sha512.Write(Curve.ElementToUint8Q(circuit.A[i].X, api, uapi))
		sha512.Write(Curve.ElementToUint8Q(circuit.A[i].Y, api, uapi))
		sha512.Write(circuit.Msg[i][:])
		//sha512.Write(Curve.ElementToUint8F(circuit.Msg[i], api, uapi))

		temp := sha512.Sum()
		/*for j := 0; j < len(temp); j++ {
			api.Println(temp[j].Val, " ")
		}*/
		k := Curve.HashToValueO(uapi, api, temp) //uapi.ToValue(uapi.PackMSB(sha256.Sum()...))

		/*api.Println("K ", k.V[0], " ", k.V[1])
		api.Println("On circuit")
		api.Println("AX ", circuit.A[i].X.V[0], " ", circuit.A[i].X.V[1])
		api.Println("AY ", circuit.A[i].Y.V[0], " ", circuit.A[i].Y.V[1])
		api.Println("RX ", circuit.R[i].X.V[0], " ", circuit.R[i].X.V[1])
		api.Println("RY ", circuit.R[i].Y.V[0], " ", circuit.R[i].Y.V[1])*/

		B := Curve.MulByScalarCircuitWithPows(Curve.GetBaseCircuit(), circuit.S[i], Curve.GetBaseCircuitPows(), api)
		//B := Curve.MulByScalarCircuit(Curve.GetBaseCircuit(), Curve.ProdElementO(circuit.S[i], Curve.StringToElementO("8"), api), api)
		//B = Curve.MulByScalarCircuit(B, Curve.StringToElementO("8"), api)
		//B = Curve.MulByScalarCircuit(B, circuit.S[i], api)
		//B = curve.ScalarMul(B, api.Mul(k, frontend.Variable(8)))

		A := Curve.MulByScalarCircuit(circuit.A[i], Curve.ProdElementO(k, Curve.StringToElementO("8"), api), api)
		//A = Curve.MulByScalarCircuit(A, Curve.StringToElementO("8"), api)
		R := circuit.R[i]
		for j := 0; j < 3; j++ {
			R = Curve.AddCircuit(R, R, api)
			B = Curve.AddCircuit(B, B, api)
		}
		A = Curve.AddCircuit(A, R, api)
		/*A := Curve.AddCircuit(
			Curve.MulByScalarCircuit(circuit.R[i], Curve.StringToElement("8"), api),
			Curve.MulByScalarCircuit(circuit.A[i], Curve.ProdElement(k, Curve.StringToElement("8"), api), api), api)
		//A := curve.Add(curve.ScalarMul(circuit.R[i], frontend.Variable(8)),
		//	curve.ScalarMul(circuit.A[i], api.Mul(k, frontend.Variable(8))))*/

		/*api.Println("DERX", A.X.V[0], " ", A.X.V[1])
		api.Println("DERY", A.Y.V[0], " ", A.Y.V[1])

		api.Println("BX ", B.X.V[0], " ", B.X.V[1])
		api.Println("BY ", B.Y.V[0], " ", B.Y.V[1])*/

		Curve.AssertEqualElementQ(A.X, B.X, api)
		Curve.AssertEqualElementQ(A.Y, B.Y, api)
		//api.AssertIsEqual(A.X, B.X)
		//api.AssertIsEqual(A.Y, B.Y)
	}
	return nil
}
