package signature_verifier

import (
	"ed25519/curve_ed25519"
	"encoding/hex"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/stretchr/testify/assert"

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"
	"math/big"

	"github.com/consensys/gnark/test"

	//"github.com/rs/zerolog"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"

	"testing"

	"crypto/ed25519"
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
	InputToCircuit(circuit, R, S, A, msg[:])
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

	sig, pk := BatchSign(msg[:], sk[:])

	/// Con las firmas y las claves publicas verifico los mensajes. Regla memotecnica: Algoritmo RSA
	circuit := NewCircuit16()
	R, S, A := BatchInputFromBytes(pk[:], sig[:])
	InputToCircuit(circuit, R, S, A, msg[:])
	assert := test.NewAssert(t)
	assert.NoError(test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()))
}

func TestSignatureBatch(t *testing.T) {
	BatchSignatureSample(t)
}

func BatchCompressSample(t *testing.T, circuit Interface) {
	nval := len(circuit.GetA())
	msg := make([][MLAR]byte, nval)
	sk := make([]*big.Int, nval)
	for nv := 0; nv < nval; nv++ {
		sk[nv], _ = crand.Int(crand.Reader, curve_ed25519.Q)
		crand.Read(msg[nv][:])
	}
	compressSig, compressPk := BatchSignCompress(msg[:], sk[:])

	/// Recupero

	R, S, A := BatchCompressToInput(compressSig, compressPk)
	InputToCircuit(circuit, R, S, A, msg[:])
	assert := test.NewAssert(t)
	assert.NoError(test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()))
}

func TestSignatureBatchCompress(t *testing.T) {
	circuit := NewCircuit16()
	BatchCompressSample(t, circuit)
}

func TestCompressedSignature(t *testing.T) {
	var messageArray [MLAR]byte
	var signArray [64]byte
	var pubKeyArray [32]byte
	message, err := hex.DecodeString("4cb77713e48d806d285188c5954c8f08210e23cab4e195161e3a82dbc5deab022ef973dc608a02e79fb5f7004979160c95154b6e0c30ec209f15ec182a8acde2c1bf6d4f6dc48fff64298e751fead01f9fa598ea571751e2a4c1375d5cac351f2a0b78ee007738d667ef673f68546f3f1e395e")
	assert.Nil(t, err)
	copy(messageArray[:], message)
	pubKey, err := hex.DecodeString("91a95d2481e41a73ac825484b52613cb755ea8906f7690fe8ddaf9cfb3856848")
	assert.Nil(t, err)
	copy(pubKeyArray[:], pubKey)

	signature, err := hex.DecodeString("68453a25c5df358a0cac5d264f905b8665aadb087e1d07b2ac9a2d1b72609e63b3042bcc8594009cf2ea2e53c2d017822e557867aa10c0c01aa3f7be31544804")
	assert.Nil(t, err)

	// assert that the input is correct, by verifying the message using non circuit cryptographic operations
	assert.True(t, ed25519.Verify(pubKey, message, signature))

	// prepare the input for the circuit
	copy(signArray[:], signature)
	R, S, A := BatchCompressToInput([][64]byte{signArray}, [][32]byte{pubKeyArray})
	msg := [][MLAR]byte{messageArray}

	// create a circuit
	circuit := NewCircuit()
	InputToCircuit(circuit, R, S, A, msg[:])
	assert := test.NewAssert(t)

	// verify
	assert.NoError(test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()))

}
