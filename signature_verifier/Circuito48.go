package signature_verifier

import (
	"ed25519/curve_ed25519"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// / Signature : R.X, R.Y, S
type Circuit48 struct {
	//R   [NVAL]curve_ed25519.PointCircuit48`gnark:",public"`
	Rc [48][32]uints.U8           `gnark:",public"`
	S  [48]curve_ed25519.ElementO `gnark:",public"`
	//A   [NVAL]curve_ed25519.PointCircuit48`gnark:",public"`
	Ac  [48][32]uints.U8   `gnark:",public"`
	Msg [48][MLAR]uints.U8 `gnark:",public"`
	//Msg [NVAL]curve_ed25519.ElementF     `gnark:",public"`
}

func (circuit *Circuit48) Define(api frontend.API) error {

	//	api.Println("CURVE Q ", curve_ed25519.Q)
	for i := 0; i < 48; i++ {

		uapi, _ := uints.New[uints.U64](api)
		R := curve_ed25519.CompressToPointCircuit(circuit.Rc[i][:], api, uapi)
		A := curve_ed25519.CompressToPointCircuit(circuit.Ac[i][:], api, uapi)

		curve_ed25519.OnCurveCircuit(R, api)
		curve_ed25519.OnCurveCircuit(A, api)

		var inputs [64 + MLAR]frontend.Variable
		for j := 0; j < 32; j++ {
			inputs[j] = circuit.Rc[i][j].Val
			inputs[j+32] = circuit.Ac[i][j].Val
		}
		for j := 0; j < MLAR; j++ {
			inputs[j+64] = circuit.Msg[i][j].Val
		}
		k := SHA2_512_MODORD(api, inputs[:])

		B := curve_ed25519.MulByScalarCircuitWithPows(curve_ed25519.GetBaseCircuit(), circuit.S[i], curve_ed25519.GetBaseCircuitPows(), api)

		A = curve_ed25519.MulByScalarCircuit(A, curve_ed25519.ProdElementO(k, curve_ed25519.StringToElementO("8"), api), api)

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

func NewCircuit48() *Circuit48 {
	return new(Circuit48)
}

func (circuit *Circuit48) GetR() [][32]uints.U8 {
	return circuit.Rc[:]
}

func (circuit *Circuit48) SetR(value [][32]uints.U8) {
	copy(circuit.Rc[:], value)
}

func (circuit *Circuit48) GetS() []curve_ed25519.ElementO {
	return circuit.S[:]
}

func (circuit *Circuit48) SetS(value []curve_ed25519.ElementO) {
	copy(circuit.S[:], value)
}

func (circuit *Circuit48) GetA() [][32]uints.U8 {
	return circuit.Ac[:]
}

func (circuit *Circuit48) SetA(value [][32]uints.U8) {
	copy(circuit.Ac[:], value)
}

func (circuit *Circuit48) GetMsg() [][MLAR]uints.U8 {
	msg := make([][MLAR]uints.U8, NVAL)
	for i := 0; i < NVAL; i++ {
		msg[i] = circuit.Msg[i]
	}
	return msg
}

func (circuit *Circuit48) SetMsg(value [][MLAR]uints.U8) {
	for i := 0; i < NVAL; i++ {
		copy(circuit.Msg[i][:], value[i][:])
	}
}
