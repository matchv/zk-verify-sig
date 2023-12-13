package signature_verifier

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const NVAL = 1

// / Signature : R.X, R.Y, S
type Circuit struct {
	Signatures [NVAL]Signature `gnark:",public"`
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

func (circuit *Circuit) GetSignatures() []Signature {
	res := make([]Signature, NVAL)
	copy(res, circuit.Signatures[:])
	return res
}

func (circuit *Circuit) SetSignatures(value []Signature) {
	copy(circuit.Signatures[:], value)
}
