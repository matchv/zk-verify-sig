package Circuito

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"

	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"

	//"github.com/rs/zerolog"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"

	"testing"
	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
)

/// run go test -v -timeout 0 to measure time

const NTests = 25

type Circuito interface {
	Define(api frontend.API) error
}

func Measures(v []time.Duration) (float64, float64) {
	var avg float64 = 0.0
	var sigma float64 = 0.0
	for i := 0; i < len(v); i++ {
		avg += v[i].Seconds()
	}
	avg = avg / float64(len(v))
	for i := 0; i < len(v); i++ {
		sigma += (v[i].Seconds() - avg) * (v[i].Seconds() - avg)
	}
	sigma = sigma / float64(len(v)-1)
	return avg, sigma
}

func Timer[C Circuito](t *testing.T, name string, New func() C) string {
	assert := test.NewAssert(t)
	p := profile.Start()
	startCompilation := time.Now()
	cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, New())
	pk, vk, _ := groth16.Setup(cs)
	compilationTime := time.Since(startCompilation)
	p.Stop()
	proofTimes := make([]time.Duration, NTests)
	verifyTimes := make([]time.Duration, NTests)

	for i := 0; i < NTests; i++ {

		asignacion := New()
		witness, errNW := frontend.NewWitness(asignacion, ecc.BN254.ScalarField())
		assert.NoError(errNW)
		startProof := time.Now()
		proof, errProve := groth16.Prove(cs, pk, witness)
		assert.NoError(errProve)
		proofTimes[i] = time.Since(startProof)
		startVerify := time.Now()
		pubWitness, _ := witness.Public()
		err := groth16.Verify(proof, vk, pubWitness)
		verifyTimes[i] = time.Since(startVerify)
		assert.NoError(err)
	}

	proofAvg, proofSigma := Measures(proofTimes)
	verifyAvg, verifySigma := Measures(verifyTimes)
	return fmt.Sprintln(name) +
		fmt.Sprintln("Compilation time: ", compilationTime.Seconds()) +
		fmt.Sprintln("Constrains: ", p.NbConstraints()) +
		fmt.Sprintln("Proof time: ", proofAvg, " ± ", proofSigma) +
		fmt.Sprintln("Verify time: ", verifyAvg, " ± ", verifySigma) +
		"=============================\n"

}

func TestTime(t *testing.T) {
	out := ""
	out = out + Timer[*Circuit](t, "NVAL = 1", Random)
	out = out + Timer[*Circuit16](t, "NVAL = 16", Random16)
	out = out + Timer[*Circuit32](t, "NVAL = 32", Random32)
	out = out + Timer[*Circuit48](t, "NVAL = 48", Random48)
	out = out + Timer[*Circuit64](t, "NVAL = 64", Random64)

	fmt.Println(out)
}
