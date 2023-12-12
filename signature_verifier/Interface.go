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

const MLAR = 115 /// d(nbConstrains)/d(MLAR) aprox 5.000
const HSIZE = 2  /// 32 bytes hash as little endian integers

type Interface interface {
	Define(api frontend.API) error
	GetR() [][32]uints.U8
	SetR(value [][32]uints.U8)
	GetS() [][32]uints.U8
	SetS(value [][32]uints.U8)
	GetA() [][32]uints.U8
	SetA(value [][32]uints.U8)
	GetMsg() [][MLAR]uints.U8
	SetMsg(value [][MLAR]uints.U8)
	GetH() [][64]uints.U8
	SetH(value [][64]uints.U8)
	GetHmain() [HSIZE]frontend.Variable
	SetHmain(value [HSIZE]frontend.Variable)
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
	tS := make([][32]uints.U8, nval)
	tH := make([][64]uints.U8, nval)
	for nv := 0; nv < nval; nv++ {
		Sha512 := csha512.New()
		for i := 0; i < MLAR; i++ {
			tMsg[nv][i] = uints.NewU8(msg[nv][i])
		}
		tA[nv] = [32]uints.U8(A[nv].CompressFormCircuit())
		tR[nv] = [32]uints.U8(R[nv].CompressFormCircuit())
		tS[nv] = [32]uints.U8(BigIntToUint8(S[nv]))
		Sha512.Write(R[nv].CompressForm())
		Sha512.Write(A[nv].CompressForm())
		Sha512.Write(msg[nv][:])
		tempH := Sha512.Sum(nil)
		for i := 0; i < 64; i++ {
			tH[nv][i] = uints.NewU8(tempH[i])
		}
		Sha256.Write(R[nv].CompressForm())
		Sha256.Write(InvertArray(S[nv].FillBytes(make([]byte, 32))))
		Sha256.Write(A[nv].CompressForm())
		Sha256.Write(msg[nv][:])
		Sha256.Write(tempH)
	}
	Hmain := InvertArray(Sha256.Sum(nil))
	var tHmain [HSIZE]frontend.Variable

	for i := 0; i < HSIZE; i++ {
		tHmain[HSIZE-1-i] = frontend.Variable(big.NewInt(0).SetBytes(Hmain[(i * 16):((i + 1) * 16)]))
	}
	circuit.SetR(tR)
	circuit.SetS(tS)
	circuit.SetA(tA)
	circuit.SetMsg(tMsg)
	circuit.SetH(tH)
	circuit.SetHmain(tHmain)
	return circuit
}

func Define(circuit Interface, api frontend.API) error {
	Rc := circuit.GetR()
	Ac := circuit.GetA()
	Sc := circuit.GetS()
	Hc := circuit.GetH()
	Msg := circuit.GetMsg()
	Sha2_256, _ := sha2.New(api)
	uapi, _ := uints.New[uints.U64](api)
	for i := 0; i < len(Rc); i++ {
		R := curve_ed25519.CompressToPointCircuit(Rc[i][:], api, uapi)
		A := curve_ed25519.CompressToPointCircuit(Ac[i][:], api, uapi)
		k := curve_ed25519.HashToValueO(api, Hc[i][:])
		S := curve_ed25519.UnsafeByteToElement[curve_ed25519.ElementO](Sc[i][:], curve_ed25519.NewElementO, api)
		B := curve_ed25519.MulByScalarCircuitWithPows(curve_ed25519.GetBaseCircuit(), S, curve_ed25519.GetBaseCircuitPows(), api)
		A = curve_ed25519.MulByScalarCircuit(A, curve_ed25519.ProdElementO(k, curve_ed25519.StringToElementO("8"), api), api)
		for j := 0; j < 3; j++ {
			R = curve_ed25519.AddCircuit(R, R, api)
			B = curve_ed25519.AddCircuit(B, B, api)
		}
		A = curve_ed25519.AddCircuit(A, R, api)
		curve_ed25519.AssertEqualElementQ(A.X, B.X, api)
		curve_ed25519.AssertEqualElementQ(A.Y, B.Y, api)

		Sha2_256.Write(Rc[i][:])
		Sha2_256.Write(Sc[i][:])
		Sha2_256.Write(Ac[i][:])
		Sha2_256.Write(Msg[i][:])
		Sha2_256.Write(Hc[i][:])
	}

	Hmain := circuit.GetHmain()
	Hloc := Sha2_256.Sum()
	var Hval [HSIZE]frontend.Variable
	for i := 0; i < HSIZE; i++ {
		Hval[i] = frontend.Variable(0)
	}
	for i := 15; i >= 0; i-- {
		for j := 0; j < HSIZE; j++ {
			Hval[j] = api.Add(api.Mul(Hval[j], frontend.Variable(256)), Hloc[i+j*16].Val)
		}
	}
	for i := 0; i < HSIZE; i++ {
		api.AssertIsEqual(Hmain[i], Hval[i])
	}
	return nil
}
