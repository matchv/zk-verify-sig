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
	H [32]uints.U8 `gnark:",public"`
}

func (circuit *Circuit48) Define(api frontend.API) error {
	return Define(circuit, api)
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
	msg := make([][MLAR]uints.U8, 32)
	for i := 0; i < 32; i++ {
		msg[i] = circuit.Msg[i]
	}
	return msg
}

func (circuit *Circuit48) SetMsg(value [][MLAR]uints.U8) {
	for i := 0; i < 32; i++ {
		copy(circuit.Msg[i][:], value[i][:])
	}
}

func (circuit *Circuit48) GetH() [32]uints.U8 {
	var h [32]uints.U8
	copy(h[:], circuit.H[:])
	return h
}

func (circuit *Circuit48) SetH(value [32]uints.U8) {
	copy(circuit.H[:], value[:])
}
