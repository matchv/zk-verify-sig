package Circuito

import (
	Curve "ed25519/src/CurveEd25519"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
)

type Circuit32 struct {
	R   [32]Curve.PointCircuit `gnark:",public"`
	S   [32]Curve.ElementO     `gnark:",public"`
	A   [32]Curve.PointCircuit `gnark:",public"`
	Msg [32][MLAR]uints.U8     `gnark:",public"`
}

func (circuit *Circuit32) Define(api frontend.API) error {
	for i := 0; i < 32; i++ {

		Curve.OnCurveCircuit(circuit.R[i], api)
		Curve.OnCurveCircuit(circuit.A[i], api)

		sha512, _ := sha3.New512(api)
		uapi, _ := uints.New[uints.U64](api)

		sha512.Write(Curve.ElementToUint8Q(circuit.R[i].X, api, uapi))
		sha512.Write(Curve.ElementToUint8Q(circuit.R[i].Y, api, uapi))
		sha512.Write(Curve.ElementToUint8Q(circuit.A[i].X, api, uapi))
		sha512.Write(Curve.ElementToUint8Q(circuit.A[i].Y, api, uapi))
		sha512.Write(circuit.Msg[i][:])

		temp := sha512.Sum()
		k := Curve.HashToValueO(uapi, api, temp)
		B := Curve.MulByScalarCircuitWithPows(Curve.GetBaseCircuit(), circuit.S[i], Curve.GetBaseCircuitPows(), api)

		A := Curve.MulByScalarCircuit(circuit.A[i], Curve.ProdElementO(k, Curve.StringToElementO("8"), api), api)
		R := circuit.R[i]
		for j := 0; j < 3; j++ {
			R = Curve.AddCircuit(R, R, api)
			B = Curve.AddCircuit(B, B, api)
		}
		A = Curve.AddCircuit(A, R, api)
		Curve.AssertEqualElementQ(A.X, B.X, api)
		Curve.AssertEqualElementQ(A.Y, B.Y, api)

	}
	return nil
}

// Getters
func (circuit *Circuit32) GetR() []Curve.PointCircuit {
	return circuit.R[:]
}

func (circuit *Circuit32) GetS() []Curve.ElementO {
	return circuit.S[:]
}

func (circuit *Circuit32) GetA() []Curve.PointCircuit {
	return circuit.A[:]
}

func (circuit *Circuit32) GetMsg() [][MLAR]uints.U8 {
	return circuit.Msg[:]
}

// Setters
func (circuit *Circuit32) SetR(values []Curve.PointCircuit) {
	copy(circuit.R[:], values)
}

func (circuit *Circuit32) SetS(values []Curve.ElementO) {
	copy(circuit.S[:], values)
}

func (circuit *Circuit32) SetA(values []Curve.PointCircuit) {
	copy(circuit.A[:], values)
}

func (circuit *Circuit32) SetMsg(values [][MLAR]uints.U8) {
	copy(circuit.Msg[:], values)
}

func NewCircuit32() *Circuit32 {
	return new(Circuit32)
}
