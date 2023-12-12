package signature_verifier

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const NVAL = 1

// / Signature : R.X, R.Y, S
type Circuit struct {
	//R   [NVAL]curve_ed25519.PointCircuit `gnark:",public"`
	Rc [NVAL][32]uints.U8 `gnark:",secret"`
	Sc [NVAL][32]uints.U8 `gnark:",secret"`
	//A   [NVAL]curve_ed25519.PointCircuit `gnark:",public"`
	Ac    [NVAL][32]uints.U8       `gnark:",secret"`
	Msg   [NVAL][MLAR]uints.U8     `gnark:",secret"`
	H     [NVAL][64]uints.U8       `gnark:",secret"`
	Hmain [HSIZE]frontend.Variable `gnark:",public"` /// Sha2_256(Ri,Si,Ai,Mi,Hi,Ri+1,...)
	//Msg [NVAL]curve_ed25519.ElementF     `gnark:",public"`
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

func (circuit *Circuit) GetS() [][32]uints.U8 {
	sc := make([][32]uints.U8, NVAL)
	copy(sc[:], circuit.Sc[:])
	return sc
}

func (circuit *Circuit) SetS(value [][32]uints.U8) {
	copy(circuit.Sc[:], value)
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

func (circuit *Circuit) GetHmain() [HSIZE]frontend.Variable {
	return circuit.Hmain
}

func (circuit *Circuit) SetHmain(value [HSIZE]frontend.Variable) {
	circuit.Hmain = value
}

func (circuit *Circuit) GetH() [][64]uints.U8 {
	h := make([][64]uints.U8, NVAL)
	copy(h[:], circuit.H[:])
	return h
}

func (circuit *Circuit) SetH(value [][64]uints.U8) {
	copy(circuit.H[:], value[:])
}
