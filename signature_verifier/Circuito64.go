package signature_verifier

import (
	"github.com/consensys/gnark/frontend"
)

type Circuit64 struct {
	Signatures [64]Signature `gnark:",public"`
}

func (circuit *Circuit64) Define(api frontend.API) error {
	return Define(circuit, api)
}

func NewCircuit64() *Circuit64 {
	return new(Circuit64)
}

func (circuit *Circuit64) GetSignatures() []Signature {
	res := make([]Signature, 64)
	copy(res, circuit.Signatures[:])
	return res
}

func (circuit *Circuit64) SetSignatures(value []Signature) {
	copy(circuit.Signatures[:], value)
}
