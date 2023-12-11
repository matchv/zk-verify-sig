package signature_verifier

import (
	"ed25519/curve_ed25519"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// / Signature : R.X, R.Y, S
type Circuit16 struct {
	//R   [NVAL]curve_ed25519.PointCircuit16`gnark:",public"`
	Rc [16][32]uints.U8           `gnark:",public"`
	S  [16]curve_ed25519.ElementO `gnark:",public"`
	//A   [NVAL]curve_ed25519.PointCircuit16`gnark:",public"`
	Ac  [16][32]uints.U8   `gnark:",public"`
	Msg [16][MLAR]uints.U8 `gnark:",public"`
	//Msg [NVAL]curve_ed25519.ElementF     `gnark:",public"`
	H [32]uints.U8 `gnark:",public"`
}

func (circuit *Circuit16) Define(api frontend.API) error {
	return Define(circuit, api)
}

func NewCircuit16() *Circuit16 {
	return new(Circuit16)
}

func (circuit *Circuit16) GetR() [][32]uints.U8 {
	return circuit.Rc[:]
}

func (circuit *Circuit16) SetR(value [][32]uints.U8) {
	copy(circuit.Rc[:], value)
}

func (circuit *Circuit16) GetS() []curve_ed25519.ElementO {
	return circuit.S[:]
}

func (circuit *Circuit16) SetS(value []curve_ed25519.ElementO) {
	copy(circuit.S[:], value)
}

func (circuit *Circuit16) GetA() [][32]uints.U8 {
	return circuit.Ac[:]
}

func (circuit *Circuit16) SetA(value [][32]uints.U8) {
	copy(circuit.Ac[:], value)
}

func (circuit *Circuit16) GetMsg() [][MLAR]uints.U8 {
	msg := make([][MLAR]uints.U8, 16)
	for i := 0; i < 16; i++ {
		msg[i] = circuit.Msg[i]
	}
	return msg
}

func (circuit *Circuit16) SetMsg(value [][MLAR]uints.U8) {
	for i := 0; i < 16; i++ {
		copy(circuit.Msg[i][:], value[i][:])
	}
}

func (circuit *Circuit16) GetH() [32]uints.U8 {
	var h [32]uints.U8
	copy(h[:], circuit.H[:])
	return h
}

func (circuit *Circuit16) SetH(value [32]uints.U8) {
	copy(circuit.H[:], value[:])
}
