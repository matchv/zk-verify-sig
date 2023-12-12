package signature_verifier

import (
	"fmt"
	"math"

	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"

	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	bn254cs "github.com/consensys/gnark/constraint/bn254"

	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

const NTests = 25

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
	return avg, math.Sqrt(sigma)
}

func TimerGrooth16[C Interface](t *testing.T, name string, New func() C) string {
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

// go  test -timeout 0s -run ^TestTimeGrooth16 -v
func TestTimeGrooth16(t *testing.T) {
	out := ""
	out = out + TimerGrooth16[*Circuit](t, "NVAL = 1", BuildRandom[*Circuit](NewCircuit))
	out = out + TimerGrooth16[*Circuit16](t, "NVAL = 16", BuildRandom[*Circuit16](NewCircuit16))
	out = out + TimerGrooth16[*Circuit32](t, "NVAL = 32", BuildRandom[*Circuit32](NewCircuit32))
	out = out + TimerGrooth16[*Circuit48](t, "NVAL = 48", BuildRandom[*Circuit48](NewCircuit48))
	out = out + TimerGrooth16[*Circuit64](t, "NVAL = 64", BuildRandom[*Circuit64](NewCircuit64))

	fmt.Println(out)
}

func TimerPlonK[C Interface](t *testing.T, name string, New func() C) string {
	assert := test.NewAssert(t)
	p := profile.Start()
	startCompilation := time.Now()
	cs, _ := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, New())
	scs := cs.(*bn254cs.SparseR1CS)
	srs, srsLagrange, _ := unsafekzg.NewSRS(scs)
	pk, vk, _ := plonk.Setup(cs, srs, srsLagrange)
	compilationTime := time.Since(startCompilation)
	p.Stop()
	proofTimes := make([]time.Duration, NTests)
	verifyTimes := make([]time.Duration, NTests)

	for i := 0; i < NTests; i++ {

		asignacion := New()
		witness, errNW := frontend.NewWitness(asignacion, ecc.BN254.ScalarField())
		assert.NoError(errNW)
		startProof := time.Now()
		proof, errProve := plonk.Prove(cs, pk, witness)
		assert.NoError(errProve)
		proofTimes[i] = time.Since(startProof)
		startVerify := time.Now()
		pubWitness, _ := witness.Public()
		err := plonk.Verify(proof, vk, pubWitness)
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

// go  test -timeout 0s -run ^TestTimePlonK -v
func TestTimePlonK(t *testing.T) {
	out := ""
	out = out + TimerPlonK[*Circuit](t, "NVAL = 1", BuildRandom[*Circuit](NewCircuit))
	out = out + TimerPlonK[*Circuit16](t, "NVAL = 16", BuildRandom[*Circuit16](NewCircuit16))
	out = out + TimerPlonK[*Circuit32](t, "NVAL = 32", BuildRandom[*Circuit32](NewCircuit32))
	out = out + TimerPlonK[*Circuit48](t, "NVAL = 48", BuildRandom[*Circuit48](NewCircuit48))
	out = out + TimerPlonK[*Circuit64](t, "NVAL = 64", BuildRandom[*Circuit64](NewCircuit64))

	fmt.Println(out)
}
