package signature_verifier

import (
	"ed25519/curve_ed25519"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"

	//"github.com/rs/zerolog"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"

	"crypto/ed25519"
	crand "crypto/rand"
	csha2 "crypto/sha512"
	"testing"
	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
)

func TestDescompressAndRecompress(t *testing.T) {
	var messageArray [MLAR]byte
	message, err := hex.DecodeString("4cb77713e48d806d285188c5954c8f08210e23cab4e195161e3a82dbc5deab022ef973dc608a02e79fb5f7004979160c95154b6e0c30ec209f15ec182a8acde2c1bf6d4f6dc48fff64298e751fead01f9fa598ea571751e2a4c1375d5cac351f2a0b78ee007738d667ef673f68546f3f1e395e")
	assert.Nil(t, err)
	copy(messageArray[:], message)
	pubKey, err := hex.DecodeString("91a95d2481e41a73ac825484b52613cb755ea8906f7690fe8ddaf9cfb3856848")
	assert.Nil(t, err)

	signature, err := hex.DecodeString("68453a25c5df358a0cac5d264f905b8665aadb087e1d07b2ac9a2d1b72609e63b3042bcc8594009cf2ea2e53c2d017822e557867aa10c0c01aa3f7be31544804")
	assert.Nil(t, err)

	// assert that the input is correct, by verifying the message using non circuit cryptographic operations
	assert.True(t, ed25519.Verify(pubKey, message, signature))

	// prepare the input for the circuit
	R, S, A := CompressToInput(signature, pubKey)

	sig, pk := InputToCompress(R, S, A)
	assert.Equal(t, signature, sig)
	assert.Equal(t, pubKey, pk)
	assert.True(t, curve_ed25519.OnCurve(R.X, R.Y))
	assert.True(t, curve_ed25519.OnCurve(A.X, A.Y))
}

func TestCompresAndDescompressRandom(t *testing.T) {
	nval := 10
	msg := make([][MLAR]byte, nval)
	sk := make([][]byte, nval)
	for nv := 0; nv < nval; nv++ {
		sk[nv] = make([]byte, 32)
		crand.Read(sk[nv][:])
		crand.Read(msg[nv][:])
	}
	compressSig, compressPk := BatchSignCompress(msg[:], sk[:])

	/// Recupero

	R, S, A := BatchCompressToInput(compressSig, compressPk)
	compressSig2, compressPk2 := BatchInputToCompress(R, S, A)
	assert.Equal(t, compressSig, compressSig2)
	assert.Equal(t, compressPk, compressPk2)
}

func TestSignCompressVsVerify(t *testing.T) {
	for nv := 0; nv < 100; nv++ {
		sk := make([]byte, 32)
		crand.Read(sk[:])
		var message [MLAR]byte
		crand.Read(message[:])
		sig, pk := SignCompress(message, sk[:32])

		sig2 := ed25519.Sign(append(sk, pk...), message[:])

		fmt.Println(len(sig), " => ", sig)
		fmt.Println(len(sig2), " => ", sig2)
		assert.Equal(t, sig, sig2)
		assert.True(t, ed25519.Verify(pk, message[:], sig))
	}
}

type CircuitSHA struct {
	K   curve_ed25519.ElementO `gnark:",public"`
	Pre [64]uints.U8
}

func (circuit *CircuitSHA) Define(api frontend.API) error {
	var med [64]frontend.Variable
	for i := 0; i < 64; i++ {
		med[i] = circuit.Pre[i].Val
	}
	k := SHA2_512_MODORD(api, med[:])
	api.Println(k.V[0], " vs ", circuit.K.V[0])
	api.Println(k.V[1], " vs ", circuit.K.V[1])
	curve_ed25519.AssertEqualElementO(k, circuit.K, api)
	return nil
}

func TestSHA2_512_MODORD(t *testing.T) {
	for nv := 0; nv < 300; nv++ {
		circuit := new(CircuitSHA)
		Pre := make([]byte, 64)
		crand.Read(Pre[:])
		sha512 := csha2.New()
		fmt.Println(Pre)
		sha512.Write(Pre[:])
		temp := InvertArray(sha512.Sum(nil))
		fmt.Println(temp)
		K := big.NewInt(0).SetBytes(temp)
		K.Mod(K, curve_ed25519.Ord)
		circuit.K = curve_ed25519.BigIntToElementO(K)
		fmt.Println(K)
		for i := 0; i < 64; i++ {
			circuit.Pre[i] = uints.NewU8(Pre[i])
		}
		assert := test.NewAssert(t)
		assert.NoError(test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()))
	}
}

func TestSignatureAndReverse(t *testing.T) {
	const nval = 64

	var msg [nval][MLAR]byte
	var sig [nval][96]byte
	var pk [nval][64]byte

	/// Proceso de firmar los mensajes
	for nv := 0; nv < nval; nv++ {
		sk := make([]byte, 32)
		crand.Read(sk[:])
		crand.Read(msg[nv][:])
		sig[nv], pk[nv] = Sign(msg[nv], sk)
	}

	/// Proceso de verificar los mensajes
	R, S, A := BatchInputFromBytes(pk[:], sig[:])

	for nv := 0; nv < nval; nv++ {
		sig2 := SignatureToBytes(R[nv], S[nv])
		pk2 := [64]byte(A[nv].Bytes())
		assert.Equal(t, sig[nv], sig2)
		assert.Equal(t, pk[nv], pk2)
	}
}

func TestSignatureCoincidence(t *testing.T) {
	const ntest = 100
	for nt := 0; nt < ntest; nt++ {
		sk := make([]byte, 32)
		crand.Read(sk[:])
		var msg [MLAR]byte
		crand.Read(msg[:])
		sig, pk := Sign(msg, sk)
		pk1 := pk[:]
		sig2, pk2 := SignCompress(msg, sk)

		R1, S1 := BytesToSignature(sig)
		A1 := curve_ed25519.BytesToPoint(pk1)

		R2, S2, A2 := CompressToInput(sig2, pk2)

		assert.Equal(t, R1, R2)
		assert.Equal(t, S1, S2)
		assert.Equal(t, A1, A2)

	}
}

func TestBachSignatureCoincidence(t *testing.T) {
	const nval = 100
	sk := make([][]byte, nval)
	msg := make([][MLAR]byte, nval)

	for nv := 0; nv < nval; nv++ {
		sk[nv] = make([]byte, 32)
		crand.Read(sk[nv][:])
		crand.Read(msg[nv][:])
	}

	sig, pk := BatchSign(msg[:], sk)
	sig2, pk2 := BatchSignCompress(msg[:], sk)

	R, S, A := BatchInputFromBytes(pk[:], sig[:])
	R2, S2, A2 := BatchCompressToInput(sig2[:], pk2[:])
	assert.Equal(t, R, R2)
	assert.Equal(t, S, S2)
	assert.Equal(t, A, A2)

}
