package Circuito

import (
	"ed25519/src/curve_ed25519"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
)

type Circuit16 struct {
	R   [16]curve_ed25519.PointCircuit `gnark:",public"`
	S   [16]curve_ed25519.ElementO     `gnark:",public"`
	A   [16]curve_ed25519.PointCircuit `gnark:",public"`
	Msg [16][MLAR]uints.U8             `gnark:",public"`
}

func (circuit *Circuit16) Define(api frontend.API) error {

	for i := 0; i < 16; i++ {

		curve_ed25519.OnCurveCircuit(circuit.R[i], api)
		curve_ed25519.OnCurveCircuit(circuit.A[i], api)

		uapi, _ := uints.New[uints.U64](api)
		sha512, _ := sha3.New512(api)
		sha512.Write(curve_ed25519.ElementToUint8Q(circuit.R[i].X, api, uapi))
		sha512.Write(curve_ed25519.ElementToUint8Q(circuit.R[i].Y, api, uapi))
		sha512.Write(curve_ed25519.ElementToUint8Q(circuit.A[i].X, api, uapi))
		sha512.Write(curve_ed25519.ElementToUint8Q(circuit.A[i].Y, api, uapi))
		sha512.Write(circuit.Msg[i][:])

		temp := sha512.Sum()
		k := curve_ed25519.HashToValueO(uapi, api, temp)

		B := curve_ed25519.MulByScalarCircuitWithPows(curve_ed25519.GetBaseCircuit(), circuit.S[i], curve_ed25519.GetBaseCircuitPows(), api)

		A := curve_ed25519.MulByScalarCircuit(circuit.A[i], curve_ed25519.ProdElementO(k, curve_ed25519.StringToElementO("8"), api), api)
		R := circuit.R[i]
		for j := 0; j < 3; j++ {
			R = curve_ed25519.AddCircuit(R, R, api)
			B = curve_ed25519.AddCircuit(B, B, api)
		}
		A = curve_ed25519.AddCircuit(A, R, api)

		curve_ed25519.AssertEqualElementQ(A.X, B.X, api)
		curve_ed25519.AssertEqualElementQ(A.Y, B.Y, api)

	}
	return nil
}

func NewCircuit16() *Circuit16 {
	return new(Circuit16)
}

// Getter para el parámetro R
func (circuit *Circuit16) GetR() []curve_ed25519.PointCircuit {
	return circuit.R[:]
}

// Setter para el parámetro R
func (circuit *Circuit16) SetR(values []curve_ed25519.PointCircuit) {
	copy(circuit.R[:], values)
}

// Getter para el parámetro S
func (circuit *Circuit16) GetS() []curve_ed25519.ElementO {
	return circuit.S[:]
}

// Setter para el parámetro S
func (circuit *Circuit16) SetS(values []curve_ed25519.ElementO) {
	copy(circuit.S[:], values)
}

// Getter para el parámetro A
func (circuit *Circuit16) GetA() []curve_ed25519.PointCircuit {
	return circuit.A[:]
}

// Setter para el parámetro A
func (circuit *Circuit16) SetA(values []curve_ed25519.PointCircuit) {
	copy(circuit.A[:], values)
}

// Getter para el parámetro Msg
func (circuit *Circuit16) GetMsg() [][MLAR]uints.U8 {
	return circuit.Msg[:]
}

// Setter para el parámetro Msg
func (circuit *Circuit16) SetMsg(values [][MLAR]uints.U8) {
	copy(circuit.Msg[:], values)
}
