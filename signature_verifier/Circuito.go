package signature_verifier

import (
	"ed25519/curve_ed25519"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
)

const NVAL = 3
const MLAR = 115 /// d(nbConstrains)/d(MLAR) aprox 5.000

// / Signature : R.X, R.Y, S
type Circuit struct {
	R   [NVAL]curve_ed25519.PointCircuit `gnark:",public"`
	S   [NVAL]curve_ed25519.ElementO     `gnark:",public"`
	A   [NVAL]curve_ed25519.PointCircuit `gnark:",public"`
	Msg [NVAL][MLAR]uints.U8             `gnark:",public"`
	//Msg [NVAL]curve_ed25519.ElementF     `gnark:",public"`
}

func Get(uapi *uints.BinaryField[uints.U64], X frontend.Variable) []uints.U8 {
	return uapi.UnpackMSB(uapi.ValueOf(X))
}

// 5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14

func (circuit *Circuit) Define(api frontend.API) error {

	//	api.Println("CURVE Q ", curve_ed25519.Q)
	for i := 0; i < NVAL; i++ {

		curve_ed25519.OnCurveCircuit(circuit.R[i], api)
		curve_ed25519.OnCurveCircuit(circuit.A[i], api)
		//curve_ed25519.AssertIsOnCurve(circuit.R[i])
		//curve_ed25519.AssertIsOnCurve(circuit.A[i])

		//api.AssertIsLessOrEqual(circuit.S[i], params.Order)
		//api.AssertIsDifferent(circuit.S[i], params.Order)

		sha512, _ := sha3.New512(api)
		uapi, _ := uints.New[uints.U64](api)

		sha512.Write(curve_ed25519.ElementToUint8Q(circuit.R[i].X, api, uapi))
		sha512.Write(curve_ed25519.ElementToUint8Q(circuit.R[i].Y, api, uapi))
		sha512.Write(curve_ed25519.ElementToUint8Q(circuit.A[i].X, api, uapi))
		sha512.Write(curve_ed25519.ElementToUint8Q(circuit.A[i].Y, api, uapi))
		sha512.Write(circuit.Msg[i][:])
		//sha512.Write(curve_ed25519.ElementToUint8F(circuit.Msg[i], api, uapi))

		temp := sha512.Sum()
		/*for j := 0; j < len(temp); j++ {
			api.Println(temp[j].Val, " ")
		}*/
		k := curve_ed25519.HashToValueO(uapi, api, temp) //uapi.ToValue(uapi.PackMSB(sha256.Sum()...))

		/*api.Println("K ", k.V[0], " ", k.V[1])
		api.Println("On circuit")
		api.Println("AX ", circuit.A[i].X.V[0], " ", circuit.A[i].X.V[1])
		api.Println("AY ", circuit.A[i].Y.V[0], " ", circuit.A[i].Y.V[1])
		api.Println("RX ", circuit.R[i].X.V[0], " ", circuit.R[i].X.V[1])
		api.Println("RY ", circuit.R[i].Y.V[0], " ", circuit.R[i].Y.V[1])*/

		B := curve_ed25519.MulByScalarCircuitWithPows(curve_ed25519.GetBaseCircuit(), circuit.S[i], curve_ed25519.GetBaseCircuitPows(), api)
		//B := curve_ed25519.MulByScalarCircuit(curve_ed25519.GetBaseCircuit(), curve_ed25519.ProdElementO(circuit.S[i], curve_ed25519.StringToElementO("8"), api), api)
		//B = curve_ed25519.MulByScalarCircuit(B, curve_ed25519.StringToElementO("8"), api)
		//B = curve_ed25519.MulByScalarCircuit(B, circuit.S[i], api)
		//B = curve_ed25519.ScalarMul(B, api.Mul(k, frontend.Variable(8)))

		A := curve_ed25519.MulByScalarCircuit(circuit.A[i], curve_ed25519.ProdElementO(k, curve_ed25519.StringToElementO("8"), api), api)
		//A = curve_ed25519.MulByScalarCircuit(A, curve_ed25519.StringToElementO("8"), api)
		R := circuit.R[i]
		for j := 0; j < 3; j++ {
			R = curve_ed25519.AddCircuit(R, R, api)
			B = curve_ed25519.AddCircuit(B, B, api)
		}
		A = curve_ed25519.AddCircuit(A, R, api)
		/*A := curve_ed25519.AddCircuit(
			curve_ed25519.MulByScalarCircuit(circuit.R[i], curve_ed25519.StringToElement("8"), api),
			curve_ed25519.MulByScalarCircuit(circuit.A[i], curve_ed25519.ProdElement(k, curve_ed25519.StringToElement("8"), api), api), api)
		//A := curve_ed25519.Add(curve_ed25519.ScalarMul(circuit.R[i], frontend.Variable(8)),
		//	curve_ed25519.ScalarMul(circuit.A[i], api.Mul(k, frontend.Variable(8))))*/

		/*api.Println("DERX", A.X.V[0], " ", A.X.V[1])
		api.Println("DERY", A.Y.V[0], " ", A.Y.V[1])

		api.Println("BX ", B.X.V[0], " ", B.X.V[1])
		api.Println("BY ", B.Y.V[0], " ", B.Y.V[1])*/

		curve_ed25519.AssertEqualElementQ(A.X, B.X, api)
		curve_ed25519.AssertEqualElementQ(A.Y, B.Y, api)
		//api.AssertIsEqual(A.X, B.X)
		//api.AssertIsEqual(A.Y, B.Y)
	}
	return nil
}

func NewCircuit() *Circuit {
	return new(Circuit)
}

func (circuit *Circuit) GetR() []curve_ed25519.PointCircuit {
	return circuit.R[:]
}

func (circuit *Circuit) SetR(value []curve_ed25519.PointCircuit) {
	copy(circuit.R[:], value)
}

func (circuit *Circuit) GetS() []curve_ed25519.ElementO {
	return circuit.S[:]
}

func (circuit *Circuit) SetS(value []curve_ed25519.ElementO) {
	copy(circuit.S[:], value)
}

func (circuit *Circuit) GetA() []curve_ed25519.PointCircuit {
	return circuit.A[:]
}

func (circuit *Circuit) SetA(value []curve_ed25519.PointCircuit) {
	copy(circuit.A[:], value)
}

func (circuit *Circuit) GetMsg() [][MLAR]uints.U8 {
	msg := make([][MLAR]uints.U8, NVAL)
	for i := 0; i < NVAL; i++ {
		msg[i] = circuit.Msg[i]
	}
	return msg
}

func (circuit *Circuit) SetMsg(value [][MLAR]uints.U8) {
	for i := 0; i < NVAL; i++ {
		copy(circuit.Msg[i][:], value[i][:])
	}
}
