package signature_verifier

import (
	"github.com/consensys/gnark/frontend"
)

type Circuit32 struct {
	Signatures [32]Signature `gnark:",public"`
}

func (circuit *Circuit32) Define(api frontend.API) error {
	return Define(circuit, api)
}

func NewCircuit32() *Circuit32 {
	return new(Circuit32)
}

func (circuit *Circuit32) GetSignatures() []Signature {
	res := make([]Signature, 32)
	copy(res, circuit.Signatures[:])
	return res
}

func (circuit *Circuit32) SetSignatures(value []Signature) {
	copy(circuit.Signatures[:], value)
}
