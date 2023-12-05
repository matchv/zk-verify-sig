package signature_verifier

import (
	"ed25519/curve_ed25519"

	"github.com/consensys/gnark-crypto/ecc"

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"
	"math/big"

	"github.com/consensys/gnark/test"

	//"github.com/rs/zerolog"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"

	"testing"

	crand "crypto/rand"
	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
)

/// Ejemplo de uso

// / Esta función muestra el proceso de firmar y verificar los mensajes
func SignatureSample(t *testing.T) {
	const nval = 16

	var msg [nval][MLAR]byte
	var sig [nval][96]byte
	var pk [nval][64]byte

	/// Proceso de firmar los mensajes
	for nv := 0; nv < nval; nv++ {
		sk, _ := crand.Int(crand.Reader, curve_ed25519.Q)
		crand.Read(msg[nv][:])
		sig[nv], pk[nv] = Sign(msg[nv], sk)
	}

	/// Proceso de verificar los mensajes
	circuit := NewCircuit16()
	R, S, A := BatchInputFromBytes(pk[:], sig[:])
	InputToCircuit[*Circuit16](circuit, R, S, A, msg[:])
	assert := test.NewAssert(t)
	assert.NoError(test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()))
}

func TestSignature(t *testing.T) {
	SignatureSample(t)
}

/// Ejemplo de uso

/// Acá se ve como usar la función para firmar en batch

func BatchSignatureSample(t *testing.T) {
	const nval = 16
	/// Creo los mensajes y claves secretas
	var msg [nval][MLAR]byte
	var sk [nval]*big.Int
	for nv := 0; nv < nval; nv++ {
		sk[nv], _ = crand.Int(crand.Reader, curve_ed25519.Q)
		crand.Read(msg[nv][:])
	}

	/// Con los mensajes y claves secretas construyo las firmas y claves publicas

	sig, pk := SignBatch(msg[:], sk[:])

	/// Con las firmas y las claves publicas verifico los mensajes. Regla memotecnica: Algoritmo RSA
	circuit := NewCircuit16()
	R, S, A := BatchInputFromBytes(pk[:], sig[:])
	InputToCircuit[*Circuit16](circuit, R, S, A, msg[:])
	assert := test.NewAssert(t)
	assert.NoError(test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()))
}

func TestSignatureBatch(t *testing.T) {
	BatchSignatureSample(t)
}
