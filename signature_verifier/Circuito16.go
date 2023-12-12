package signature_verifier

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// / Signature : R.X, R.Y, S
type Circuit16 struct {
	Rc    [16][32]uints.U8         `gnark:",secret"`
	Sc    [16][32]uints.U8         `gnark:",secret"`
	Ac    [16][32]uints.U8         `gnark:",secret"`
	Msg   [16][MLAR]uints.U8       `gnark:",secret"`
	H     [16][64]uints.U8         `gnark:",secret"`
	Hmain [HSIZE]frontend.Variable `gnark:",public"`
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

func (circuit *Circuit16) GetS() [][32]uints.U8 {
	sc := make([][32]uints.U8, 16)
	copy(sc[:], circuit.Sc[:])
	return sc
}

func (circuit *Circuit16) SetS(value [][32]uints.U8) {
	copy(circuit.Sc[:], value)
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

func (circuit *Circuit16) GetHmain() [HSIZE]frontend.Variable {
	return circuit.Hmain
}

func (circuit *Circuit16) SetHmain(value [HSIZE]frontend.Variable) {
	circuit.Hmain = value
}

func (circuit *Circuit16) GetH() [][64]uints.U8 {
	h := make([][64]uints.U8, 16)
	copy(h[:], circuit.H[:])
	return h
}

func (circuit *Circuit16) SetH(value [][64]uints.U8) {
	copy(circuit.H[:], value[:])
}
