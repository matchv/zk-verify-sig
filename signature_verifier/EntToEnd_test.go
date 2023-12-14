package signature_verifier

import (
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func ExportGrooth16[C Interface](t *testing.T, New func() C) {
	assert := test.NewAssert(t)
	cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, New())
	pk, vk, _ := groth16.Setup(cs)

	asignacion := New()
	witness, errNW := frontend.NewWitness(asignacion, ecc.BN254.ScalarField())
	assert.NoError(errNW)
	proof, errProve := groth16.Prove(cs, pk, witness)
	assert.NoError(errProve)
	pubWitness, _ := witness.Public()
	err := groth16.Verify(proof, vk, pubWitness)
	assert.NoError(err)

	f, _ := os.Create("vk.sol")
	vk.ExportSolidity(f)

}
func TestExportAndVerify(t *testing.T) {
	ExportGrooth16[*Circuit](t, NewCircuit)
}
