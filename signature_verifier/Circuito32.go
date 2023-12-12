package signature_verifier

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// / Signature : R.X, R.Y, S
type Circuit32 struct {
	Rc    [32][32]uints.U8         `gnark:",secret"`
	Sc    [32][32]uints.U8         `gnark:",secret"`
	Ac    [32][32]uints.U8         `gnark:",secret"`
	Msg   [32][MLAR]uints.U8       `gnark:",secret"`
	H     [32][64]uints.U8         `gnark:",secret"`
	Hmain [HSIZE]frontend.Variable `gnark:",public"`
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

func (circuit *Circuit32) GetS() [][32]uints.U8 {
	sc := make([][32]uints.U8, 32)
	copy(sc[:], circuit.Sc[:])
	return sc
}

func (circuit *Circuit32) SetS(value [][32]uints.U8) {
	copy(circuit.Sc[:], value)
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

func (circuit *Circuit32) GetHmain() [HSIZE]frontend.Variable {
	return circuit.Hmain
}

func (circuit *Circuit32) SetHmain(value [HSIZE]frontend.Variable) {
	circuit.Hmain = value
}

func (circuit *Circuit32) GetH() [][64]uints.U8 {
	h := make([][64]uints.U8, 32)
	copy(h[:], circuit.H[:])
	return h
}

func (circuit *Circuit32) SetH(value [][64]uints.U8) {
	copy(circuit.H[:], value[:])
}
