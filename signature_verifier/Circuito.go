package signature_verifier

import (
	"ed25519/curve_ed25519"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const NVAL = 1
const MLAR = 115 /// d(nbConstrains)/d(MLAR) aprox 5.000

// / Signature : R.X, R.Y, S
type Circuit struct {
	//R   [NVAL]curve_ed25519.PointCircuit `gnark:",public"`
	Rc [NVAL][32]uints.U8           `gnark:",public"`
	S  [NVAL]curve_ed25519.ElementO `gnark:",public"`
	//A   [NVAL]curve_ed25519.PointCircuit `gnark:",public"`
	Ac  [NVAL][32]uints.U8   `gnark:",public"`
	Msg [NVAL][MLAR]uints.U8 `gnark:",public"`
	//Msg [NVAL]curve_ed25519.ElementF     `gnark:",public"`
	H [32]uints.U8 `gnark:",public"`
}

func Get(uapi *uints.BinaryField[uints.U64], X frontend.Variable) []uints.U8 {
	return uapi.UnpackMSB(uapi.ValueOf(X))
}

// 5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14

func (circuit *Circuit) Define(api frontend.API) error {
	return Define(circuit, api)
}

func NewCircuit() *Circuit {
	return new(Circuit)
}

func (circuit *Circuit) GetR() [][32]uints.U8 {
	return circuit.Rc[:]
}

func (circuit *Circuit) SetR(value [][32]uints.U8) {
	copy(circuit.Rc[:], value)
}

func (circuit *Circuit) GetS() []curve_ed25519.ElementO {
	return circuit.S[:]
}

func (circuit *Circuit) SetS(value []curve_ed25519.ElementO) {
	copy(circuit.S[:], value)
}

func (circuit *Circuit) GetA() [][32]uints.U8 {
	return circuit.Ac[:]
}

func (circuit *Circuit) SetA(value [][32]uints.U8) {
	copy(circuit.Ac[:], value)
}

func (circuit *Circuit) GetMsg() [][MLAR]uints.U8 {
	msg := make([][MLAR]uints.U8, NVAL)
	for i := 0; i < NVAL; i++ {
		msg[i] = circuit.Msg[i]
	}
	return msg
}

func (circuit *Circuit) SetMsg(value [][MLAR]uints.U8) {
	for i := 0; i < NVAL; i++ {
		copy(circuit.Msg[i][:], value[i][:])
	}
}

func (circuit *Circuit) GetH() [32]uints.U8 {
	var h [32]uints.U8
	copy(h[:], circuit.H[:])
	return h
}

func (circuit *Circuit) SetH(value [32]uints.U8) {
	copy(circuit.H[:], value[:])
}
