package signature_verifier

import (
	"ed25519/curve_ed25519"
	"math/big"

	crand "crypto/rand"

	csha3 "golang.org/x/crypto/sha3"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type Interface interface {
	Define(api frontend.API) error
	GetR() []curve_ed25519.PointCircuit
	SetR(value []curve_ed25519.PointCircuit)
	GetS() []curve_ed25519.ElementO
	SetS(value []curve_ed25519.ElementO)
	GetA() []curve_ed25519.PointCircuit
	SetA(value []curve_ed25519.PointCircuit)
	GetMsg() [][MLAR]uints.U8
	SetMsg(value [][MLAR]uints.U8)
}

func BuildRandom[C Interface](nuevo func() C) func() C {
	Random := func() C {
		circuit := nuevo()
		nval := len(circuit.GetR())
		tMsg := make([][MLAR]uints.U8, nval)
		tA := make([]curve_ed25519.PointCircuit, nval)
		tR := make([]curve_ed25519.PointCircuit, nval)
		tS := make([]curve_ed25519.ElementO, nval)
		for nv := 0; nv < nval; nv++ {
			sk, _ := crand.Int(crand.Reader, curve_ed25519.Q)
			var m [MLAR]byte
			crand.Read(m[:])
			for i := 0; i < MLAR; i++ {
				tMsg[nv][i] = uints.NewU8(m[i])
			}

			sha512 := csha3.New512()
			sha512.Write(sk.Bytes())
			H := sha512.Sum(nil)
			s := new(big.Int).SetBytes(H[0:32])
			A := curve_ed25519.IntToPoint(s)
			tA[nv] = curve_ed25519.PointToCircuit(A)

			prefix := H[32:64]
			sha512.Reset()
			sha512.Write(prefix)
			sha512.Write(m[:])
			r := new(big.Int).SetBytes(sha512.Sum(nil))
			r = r.Mul(r, big.NewInt(8))
			r = r.Mod(r, curve_ed25519.Ord)

			R := curve_ed25519.IntToPoint(r)
			tR[nv] = curve_ed25519.PointToCircuit(R)
			sha512.Reset()
			sha512.Write(R.Bytes())
			sha512.Write(A.Bytes())
			sha512.Write(m[:])
			k := new(big.Int).SetBytes(sha512.Sum(nil))
			k = k.Mod(k, curve_ed25519.Ord)

			S := big.NewInt(0).Add(big.NewInt(0).Mul(k, s), r)
			S.Mod(S, curve_ed25519.Ord)
			tS[nv] = curve_ed25519.BigIntToElementO(S)
		}
		circuit.SetR(tR)
		circuit.SetS(tS)
		circuit.SetA(tA)
		circuit.SetMsg(tMsg)
		return circuit
	}
	return Random
}

func InputToCircuit(circuit Interface, R []curve_ed25519.Point, S []*big.Int, A []curve_ed25519.Point, msg [][MLAR]byte) Interface {
	nval := len(A)
	tMsg := make([][MLAR]uints.U8, nval)
	tA := make([]curve_ed25519.PointCircuit, nval)
	tR := make([]curve_ed25519.PointCircuit, nval)
	tS := make([]curve_ed25519.ElementO, nval)
	for nv := 0; nv < nval; nv++ {
		for i := 0; i < MLAR; i++ {
			tMsg[nv][i] = uints.NewU8(msg[nv][i])
		}
		tA[nv] = curve_ed25519.PointToCircuit(A[nv])
		tR[nv] = curve_ed25519.PointToCircuit(R[nv])
		tS[nv] = curve_ed25519.BigIntToElementO(S[nv])
	}
	circuit.SetR(tR)
	circuit.SetS(tS)
	circuit.SetA(tA)
	circuit.SetMsg(tMsg)
	return circuit
}
