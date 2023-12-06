package signature_verifier

import (
	"ed25519/curve_ed25519"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
)

type Circuit48 struct {
	R   [48]curve_ed25519.PointCircuit `gnark:",public"`
	S   [48]curve_ed25519.ElementO     `gnark:",public"`
	A   [48]curve_ed25519.PointCircuit `gnark:",public"`
	Msg [48][MLAR]uints.U8             `gnark:",public"`
}

func (circuit *Circuit48) Define(api frontend.API) error {

	for i := 0; i < 48; i++ {

		curve_ed25519.OnCurveCircuit(circuit.R[i], api)
		curve_ed25519.OnCurveCircuit(circuit.A[i], api)
		sha512, _ := sha3.New512(api)
		uapi, _ := uints.New[uints.U64](api)

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

func (circuit *Circuit48) GetR() []curve_ed25519.PointCircuit {
	return circuit.R[:]
}

func (circuit *Circuit48) SetR(values []curve_ed25519.PointCircuit) {
	copy(circuit.R[:], values)
}
func (circuit *Circuit48) GetS() []curve_ed25519.ElementO {
	return circuit.S[:]
}

func (circuit *Circuit48) SetS(values []curve_ed25519.ElementO) {
	copy(circuit.S[:], values)
}

func (circuit *Circuit48) GetA() []curve_ed25519.PointCircuit {
	return circuit.A[:]
}

func (circuit *Circuit48) SetA(values []curve_ed25519.PointCircuit) {
	copy(circuit.A[:], values)
}

func (circuit *Circuit48) GetMsg() [][MLAR]uints.U8 {
	return circuit.Msg[:]
}

func (circuit *Circuit48) SetMsg(values [][MLAR]uints.U8) {
	copy(circuit.Msg[:], values)
}

func NewCircuit48() *Circuit48 {
	return new(Circuit48)
}