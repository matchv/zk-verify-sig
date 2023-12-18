package main

import (
	"bytes"
	"encoding/hex"
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// CubicCircuit defines a simple circuit
// x**3 + x + 5 == y
type CubicCircuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *CubicCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func main() {
	// compiles our circuit into a R1CS
	var circuit CubicCircuit
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	// witness definition
	assignment := CubicCircuit{X: 3, Y: 35}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)

	// generate sol
	f, _ := os.Create("solidity/test/src/Verifier.sol")
	defer f.Close()

	var pb1 bytes.Buffer
	var pb2 bytes.Buffer

	_, err := proof.WriteRawTo(&pb1)
	if err != nil {
		log.Fatal(err)
	}
	_, err = publicWitness.WriteTo(&pb2)
	if err != nil {
		log.Fatal(err)
	}

	// NOTE: it's important to understand that the proofs are circuit specific
	// so every time we run this script, a new {prover, verifier, proof} are created.
	// Therefore, only call ExportSolidity when the proof + public witness will also be
	// updated on the foundry test

	log.Println(hex.EncodeToString(pb1.Bytes()))
	log.Println(hex.EncodeToString(pb2.Bytes()))

	vk.ExportSolidity(f)

	// lala

}
