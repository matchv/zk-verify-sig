package signature_verifier

import (
	"ed25519/curve_ed25519"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// / Signature : R.X, R.Y, S
type Circuit64 struct {
	//R   [NVAL]curve_ed25519.PointCircuit64`gnark:",public"`
	Rc [64][32]uints.U8           `gnark:",public"`
	S  [64]curve_ed25519.ElementO `gnark:",public"`
	//A   [NVAL]curve_ed25519.PointCircuit64`gnark:",public"`
	Ac  [64][32]uints.U8   `gnark:",public"`
	Msg [64][MLAR]uints.U8 `gnark:",public"`
	//Msg [NVAL]curve_ed25519.ElementF     `gnark:",public"`
	H [32]uints.U8 `gnark:",public"`
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

func (circuit *Circuit64) GetS() []curve_ed25519.ElementO {
	return circuit.S[:]
}

func (circuit *Circuit64) SetS(value []curve_ed25519.ElementO) {
	copy(circuit.S[:], value)
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

func (circuit *Circuit64) GetH() [32]uints.U8 {
	var h [32]uints.U8
	copy(h[:], circuit.H[:])
	return h
}

func (circuit *Circuit64) SetH(value [32]uints.U8) {
	copy(circuit.H[:], value[:])
}
