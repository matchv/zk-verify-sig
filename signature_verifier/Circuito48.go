package signature_verifier

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// / Signature : R.X, R.Y, S
type Circuit48 struct {
	Rc    [48][32]uints.U8         `gnark:",secret"`
	Sc    [48][32]uints.U8         `gnark:",secret"`
	Ac    [48][32]uints.U8         `gnark:",secret"`
	Msg   [48][MLAR]uints.U8       `gnark:",secret"`
	H     [48][64]uints.U8         `gnark:",secret"`
	Hmain [HSIZE]frontend.Variable `gnark:",public"`
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

func (circuit *Circuit48) GetS() [][32]uints.U8 {
	sc := make([][32]uints.U8, 48)
	copy(sc[:], circuit.Sc[:])
	return sc
}

func (circuit *Circuit48) SetS(value [][32]uints.U8) {
	copy(circuit.Sc[:], value)
}

func (circuit *Circuit48) GetA() [][32]uints.U8 {
	return circuit.Ac[:]
}

func (circuit *Circuit48) SetA(value [][32]uints.U8) {
	copy(circuit.Ac[:], value)
}

func (circuit *Circuit48) GetMsg() [][MLAR]uints.U8 {
	msg := make([][MLAR]uints.U8, 48)
	for i := 0; i < 48; i++ {
		msg[i] = circuit.Msg[i]
	}
	return msg
}

func (circuit *Circuit48) SetMsg(value [][MLAR]uints.U8) {
	for i := 0; i < 48; i++ {
		copy(circuit.Msg[i][:], value[i][:])
	}
}

func (circuit *Circuit48) GetHmain() [HSIZE]frontend.Variable {
	return circuit.Hmain
}

func (circuit *Circuit48) SetHmain(value [HSIZE]frontend.Variable) {
	circuit.Hmain = value
}

func (circuit *Circuit48) GetH() [][64]uints.U8 {
	h := make([][64]uints.U8, 48)
	copy(h[:], circuit.H[:])
	return h
}

func (circuit *Circuit48) SetH(value [][64]uints.U8) {
	copy(circuit.H[:], value[:])
}
