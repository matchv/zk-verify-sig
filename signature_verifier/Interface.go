package signature_verifier

import (
	"ed25519/curve_ed25519"
	"math/big"

	crand "crypto/rand"
	csha256 "crypto/sha256"
	csha512 "crypto/sha512"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

type Interface interface {
	Define(api frontend.API) error
	GetR() [][32]uints.U8
	SetR(value [][32]uints.U8)
	GetS() []curve_ed25519.ElementO
	SetS(value []curve_ed25519.ElementO)
	GetA() [][32]uints.U8
	SetA(value [][32]uints.U8)
	GetMsg() [][MLAR]uints.U8
	SetMsg(value [][MLAR]uints.U8)
	GetH() [32]uints.U8
	SetH(value [32]uints.U8)
}

func BuildRandom[C Interface](nuevo func() C) func() C {

	Random := func() C {
		circuit := nuevo()
		nval := len(circuit.GetR())
		Msg := make([][MLAR]byte, nval)
		sk := make([][]byte, nval)
		for nv := 0; nv < nval; nv++ {
			sk[nv] = make([]byte, 32)
			crand.Read(sk[nv][:])
			crand.Read(Msg[nv][:])
		}
		sig, pk := BatchSign(Msg[:], sk[:])
		R, S, A := BatchInputFromBytes(pk[:], sig[:])
		InputToCircuit(circuit, R, S, A, Msg)
		return circuit
	}
	return Random
}

func InputToCircuit(circuit Interface, R []curve_ed25519.Point, S []*big.Int, A []curve_ed25519.Point, msg [][MLAR]byte) Interface {
	Sha256 := csha256.New()

	nval := len(A)
	tMsg := make([][MLAR]uints.U8, nval)
	tA := make([][32]uints.U8, nval)
	tR := make([][32]uints.U8, nval)
	tS := make([]curve_ed25519.ElementO, nval)
	tH := [32]uints.U8{}
	for nv := 0; nv < nval; nv++ {
		Sha512 := csha512.New()
		for i := 0; i < MLAR; i++ {
			tMsg[nv][i] = uints.NewU8(msg[nv][i])
		}
		tA[nv] = [32]uints.U8(A[nv].CompressFormCircuit())
		tR[nv] = [32]uints.U8(R[nv].CompressFormCircuit())
		tS[nv] = curve_ed25519.BigIntToElementO(S[nv])
		Sha512.Write(R[nv].CompressForm())
		Sha512.Write(A[nv].CompressForm())
		Sha512.Write(msg[nv][:])
		tempH := Sha512.Sum(nil)
		Sha256.Write(tempH)
	}
	H := Sha256.Sum(nil)
	for i := 0; i < 32; i++ {
		tH[i] = uints.NewU8(H[i])
	}

	circuit.SetR(tR)
	circuit.SetS(tS)
	circuit.SetA(tA)
	circuit.SetMsg(tMsg)
	circuit.SetH(tH)
	return circuit
}

func Define(circuit Interface, api frontend.API) error {
	Rc := circuit.GetR()
	Ac := circuit.GetA()
	S := circuit.GetS()
	Msg := circuit.GetMsg()
	Sha2_256, _ := sha2.New(api)
	uapi, _ := uints.New[uints.U64](api)
	for i := 0; i < len(Rc); i++ {
		R := curve_ed25519.CompressToPointCircuit(Rc[i][:], api, uapi)
		A := curve_ed25519.CompressToPointCircuit(Ac[i][:], api, uapi)
		var inputs [64 + MLAR]frontend.Variable
		for j := 0; j < 32; j++ {
			inputs[j] = Rc[i][j].Val
			inputs[j+32] = Ac[i][j].Val
		}
		for j := 0; j < MLAR; j++ {
			inputs[j+64] = Msg[i][j].Val
		}
		temp := SHA2_512(uapi, api, inputs[:])
		Sha2_256.Write(temp[:])
		k := curve_ed25519.HashToValueO(api, temp[:])
		B := curve_ed25519.MulByScalarCircuitWithPows(curve_ed25519.GetBaseCircuit(), S[i], curve_ed25519.GetBaseCircuitPows(), api)
		A = curve_ed25519.MulByScalarCircuit(A, curve_ed25519.ProdElementO(k, curve_ed25519.StringToElementO("8"), api), api)
		for j := 0; j < 3; j++ {
			R = curve_ed25519.AddCircuit(R, R, api)
			B = curve_ed25519.AddCircuit(B, B, api)
		}
		A = curve_ed25519.AddCircuit(A, R, api)
		curve_ed25519.AssertEqualElementQ(A.X, B.X, api)
		curve_ed25519.AssertEqualElementQ(A.Y, B.Y, api)
	}

	H := circuit.GetH()
	Hloc := Sha2_256.Sum()
	for i := 0; i < 32; i++ {
		uapi.ByteAssertEq(H[i], Hloc[i])
	}
	return nil
}
