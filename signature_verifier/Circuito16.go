package signature_verifier

import (
	"github.com/consensys/gnark/frontend"
)

type Circuit16 struct {
	Signatures [16]Signature `gnark:",public"`
}

func (circuit *Circuit16) Define(api frontend.API) error {
	return Define(circuit, api)
}

func NewCircuit16() *Circuit16 {
	return new(Circuit16)
}

func (circuit *Circuit16) GetSignatures() []Signature {
	res := make([]Signature, 16)
	copy(res, circuit.Signatures[:])
	return res
}

func (circuit *Circuit16) SetSignatures(value []Signature) {
	copy(circuit.Signatures[:], value)
}
