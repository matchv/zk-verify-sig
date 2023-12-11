package signature_verifier

import (
	"ed25519/curve_ed25519"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// / Signature : R.X, R.Y, S
type Circuit32 struct {
	//R   [NVAL]curve_ed25519.PointCircuit32`gnark:",public"`
	Rc [32][32]uints.U8           `gnark:",public"`
	S  [32]curve_ed25519.ElementO `gnark:",public"`
	//A   [NVAL]curve_ed25519.PointCircuit32`gnark:",public"`
	Ac  [32][32]uints.U8   `gnark:",public"`
	Msg [32][MLAR]uints.U8 `gnark:",public"`
	//Msg [NVAL]curve_ed25519.ElementF     `gnark:",public"`
	H [32]uints.U8 `gnark:",public"`
}

func (circuit *Circuit32) Define(api frontend.API) error {
	return Define(circuit, api)
}

func NewCircuit32() *Circuit32 {
	return new(Circuit32)
}

func (circuit *Circuit32) GetR() [][32]uints.U8 {
	return circuit.Rc[:]
}

func (circuit *Circuit32) SetR(value [][32]uints.U8) {
	copy(circuit.Rc[:], value)
}

func (circuit *Circuit32) GetS() []curve_ed25519.ElementO {
	return circuit.S[:]
}

func (circuit *Circuit32) SetS(value []curve_ed25519.ElementO) {
	copy(circuit.S[:], value)
}

func (circuit *Circuit32) GetA() [][32]uints.U8 {
	return circuit.Ac[:]
}

func (circuit *Circuit32) SetA(value [][32]uints.U8) {
	copy(circuit.Ac[:], value)
}

func (circuit *Circuit32) GetMsg() [][MLAR]uints.U8 {
	msg := make([][MLAR]uints.U8, 32)
	for i := 0; i < 32; i++ {
		msg[i] = circuit.Msg[i]
	}
	return msg
}

func (circuit *Circuit32) SetMsg(value [][MLAR]uints.U8) {
	for i := 0; i < 32; i++ {
		copy(circuit.Msg[i][:], value[i][:])
	}
}

func (circuit *Circuit32) GetH() [32]uints.U8 {
	var h [32]uints.U8
	copy(h[:], circuit.H[:])
	return h
}

func (circuit *Circuit32) SetH(value [32]uints.U8) {
	copy(circuit.H[:], value[:])
}
