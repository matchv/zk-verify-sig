package signature_verifier

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// / Signature : R.X, R.Y, S
type Circuit64 struct {
	Rc    [64][32]uints.U8         `gnark:",secret"`
	Sc    [64][32]uints.U8         `gnark:",secret"`
	Ac    [64][32]uints.U8         `gnark:",secret"`
	Msg   [64][MLAR]uints.U8       `gnark:",secret"`
	H     [64][64]uints.U8         `gnark:",secret"`
	Hmain [HSIZE]frontend.Variable `gnark:",public"`
}

func (circuit *Circuit64) Define(api frontend.API) error {
	return Define(circuit, api)
}

func NewCircuit64() *Circuit64 {
	return new(Circuit64)
}

func (circuit *Circuit64) GetR() [][32]uints.U8 {
	return circuit.Rc[:]
}

func (circuit *Circuit64) SetR(value [][32]uints.U8) {
	copy(circuit.Rc[:], value)
}

func (circuit *Circuit64) GetS() [][32]uints.U8 {
	sc := make([][32]uints.U8, 64)
	copy(sc[:], circuit.Sc[:])
	return sc
}

func (circuit *Circuit64) SetS(value [][32]uints.U8) {
	copy(circuit.Sc[:], value)
}

func (circuit *Circuit64) GetA() [][32]uints.U8 {
	return circuit.Ac[:]
}

func (circuit *Circuit64) SetA(value [][32]uints.U8) {
	copy(circuit.Ac[:], value)
}

func (circuit *Circuit64) GetMsg() [][MLAR]uints.U8 {
	msg := make([][MLAR]uints.U8, 64)
	for i := 0; i < 64; i++ {
		msg[i] = circuit.Msg[i]
	}
	return msg
}

func (circuit *Circuit64) SetMsg(value [][MLAR]uints.U8) {
	for i := 0; i < 64; i++ {
		copy(circuit.Msg[i][:], value[i][:])
	}
}

func (circuit *Circuit64) GetHmain() [HSIZE]frontend.Variable {
	return circuit.Hmain
}

func (circuit *Circuit64) SetHmain(value [HSIZE]frontend.Variable) {
	circuit.Hmain = value
}

func (circuit *Circuit64) GetH() [][64]uints.U8 {
	h := make([][64]uints.U8, 64)
	copy(h[:], circuit.H[:])
	return h
}

func (circuit *Circuit64) SetH(value [][64]uints.U8) {
	copy(circuit.H[:], value[:])
}
