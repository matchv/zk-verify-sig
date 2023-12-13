package signature_verifier

import (
	"ed25519/curve_ed25519"
	"math/big"

	crand "crypto/rand"
	csha256 "crypto/sha256"
	csha512 "crypto/sha512"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const MLAR = 115 /// d(nbConstrains)/d(MLAR) aprox 5.000
const HSIZE = 2  /// 32 bytes hash as little endian integers

type Interface interface {
	Define(api frontend.API) error
	GetSignatures() []Signature
	SetSignatures([]Signature)
}

func RandomInput(nval int) (R []curve_ed25519.Point, S []*big.Int, A []curve_ed25519.Point, Msg [][MLAR]byte) {
	Msg = make([][MLAR]byte, nval)
	sk := make([][]byte, nval)
	for nv := 0; nv < nval; nv++ {
		sk[nv] = make([]byte, 32)
		crand.Read(sk[nv][:])
		crand.Read(Msg[nv][:])
	}
	sig, pk := BatchSign(Msg[:], sk[:])
	R, S, A = BatchInputFromBytes(pk[:], sig[:])
	return
}

func BuildRandom[C Interface](nuevo func() C) func() C {
	Random := func() C {
		circuit := nuevo()
		nval := len(circuit.GetSignatures())
		R, S, A, Msg := RandomInput(nval)
		InputToCircuit(circuit, R, S, A, Msg)
		return circuit
	}
	return Random
}

func InputToCircuit(circuit Interface, R []curve_ed25519.Point, S []*big.Int, A []curve_ed25519.Point, msg [][MLAR]byte) Interface {
	Sha256 := csha256.New()

	nval := len(A)
	tSig := make([]Signature, nval)
	for nv := 0; nv < nval; nv++ {
		Sha512 := csha512.New()
		tSig[nv].SetAll(R[nv], S[nv], A[nv], msg[nv])
		Sha512.Write(R[nv].CompressForm())
		Sha512.Write(A[nv].CompressForm())
		Sha512.Write(msg[nv][:])
		tempH := Sha512.Sum(nil)
		Sha256.Write(tempH)
	}
	circuit.SetSignatures(tSig)
	return circuit
}

func ConcatenateRAM(Rc, Ac [32]uints.U8, M [MLAR]uints.U8) []frontend.Variable {
	output := make([]frontend.Variable, 64+MLAR)
	for i := 0; i < 32; i++ {
		output[i] = Rc[i].Val
		output[i+32] = Ac[i].Val
	}
	for i := 0; i < MLAR; i++ {
		output[i+64] = M[i].Val
	}
	return output
}

func Define(circuit Interface, api frontend.API) error {
	Sig := circuit.GetSignatures()
	//Msg := circuit.GetMsg()
	uapi, _ := uints.New[uints.U64](api)
	for i := 0; i < len(Sig); i++ {
		Rc, Sc, Ac, M := Sig[i].GetAllCircuit(uapi, api)
		R := curve_ed25519.CompressToPointCircuit(Rc[:], api, uapi)
		A := curve_ed25519.CompressToPointCircuit(Ac[:], api, uapi)
		khash := SHA2_512Circuit(uapi, api, ConcatMultipleSlices(Rc[:], Ac[:], M[:]))
		k := curve_ed25519.HashToValueO(api, khash[:])
		S := curve_ed25519.UnsafeByteToElement[curve_ed25519.ElementO](Sc[:], curve_ed25519.NewElementO, api)
		B := curve_ed25519.MulByScalarCircuitWithPows(curve_ed25519.GetBaseCircuit(), S, curve_ed25519.GetBaseCircuitPows(), api)
		A = curve_ed25519.MulByScalarCircuit(A, curve_ed25519.ProdElementO(k, curve_ed25519.StringToElementO("8"), api), api)
		for j := 0; j < 3; j++ {
			R = curve_ed25519.AddCircuit(R, R, api)
			B = curve_ed25519.AddCircuit(B, B, api)
		}
		A = curve_ed25519.AddCircuit(A, R, api)
		curve_ed25519.AssertEqualElementQ(A.X, B.X, api)
		curve_ed25519.AssertEqualElementQ(A.Y, B.Y, api)
	}
	return nil
}
