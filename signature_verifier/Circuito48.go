package signature_verifier

import (
	"github.com/consensys/gnark/frontend"
)

type Circuit48 struct {
	Signatures [48]Signature `gnark:",public"`
}

func (circuit *Circuit48) Define(api frontend.API) error {
	return Define(circuit, api)
}

func NewCircuit48() *Circuit48 {
	return new(Circuit48)
}

func (circuit *Circuit48) GetSignatures() []Signature {
	return circuit.Signatures[:]
}

func (circuit *Circuit48) SetSignatures(value []Signature) {
	copy(circuit.Signatures[:], value)
}
