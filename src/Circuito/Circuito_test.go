package Circuito

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	//"github.com/rs/zerolog"
	"testing"
)

func TestMyMerkle(t *testing.T) {
	assert := test.NewAssert(t)

	var circuito Circuit

	assert.SolvingSucceeded(&circuito, &Circuit{}, test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))

	assert.SolvingFailed(&circuito, &Circuit{}, test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))
}
