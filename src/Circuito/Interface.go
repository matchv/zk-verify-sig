package Circuito

import (
	Curve "ed25519/src/CurveEd25519"
	"math/big"

	crand "crypto/rand"

	csha3 "golang.org/x/crypto/sha3"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type Interface interface {
	Define(api frontend.API) error
	GetR() []Curve.PointCircuit
	SetR(value []Curve.PointCircuit)
	GetS() []Curve.ElementO
	SetS(value []Curve.ElementO)
	GetA() []Curve.PointCircuit
	SetA(value []Curve.PointCircuit)
	GetMsg() [][MLAR]uints.U8
	SetMsg(value [][MLAR]uints.U8)
}

func BuildRandom[C Interface](nuevo func() C) func() C {
	Random := func() C {
		circuit := nuevo()
		nval := len(circuit.GetR())
		tMsg := make([][MLAR]uints.U8, nval)
		tA := make([]Curve.PointCircuit, nval)
		tR := make([]Curve.PointCircuit, nval)
		tS := make([]Curve.ElementO, nval)
		for nv := 0; nv < nval; nv++ {
			sk, _ := crand.Int(crand.Reader, Curve.Q)
			var m [MLAR]byte
			crand.Read(m[:])
			for i := 0; i < MLAR; i++ {
				tMsg[nv][i] = uints.NewU8(m[i])
			}

			sha512 := csha3.New512()
			sha512.Write(sk.Bytes())
			H := sha512.Sum(nil)
			s := new(big.Int).SetBytes(H[0:32])
			A := Curve.IntToPoint(s)
			tA[nv] = Curve.PointToCircuit(A)

			prefix := H[32:64]
			sha512.Reset()
			sha512.Write(prefix)
			sha512.Write(m[:])
			r := new(big.Int).SetBytes(sha512.Sum(nil))
			r = r.Mul(r, big.NewInt(8))
			r = r.Mod(r, Curve.Ord)

			R := Curve.IntToPoint(r)
			tR[nv] = Curve.PointToCircuit(R)
			sha512.Reset()
			sha512.Write(R.Bytes())
			sha512.Write(A.Bytes())
			sha512.Write(m[:])
			k := new(big.Int).SetBytes(sha512.Sum(nil))
			k = k.Mod(k, Curve.Ord)

			S := big.NewInt(0).Add(big.NewInt(0).Mul(k, s), r)
			S.Mod(S, Curve.Ord)
			tS[nv] = Curve.BigIntToElementO(S)
		}
		circuit.SetR(tR)
		circuit.SetS(tS)
		circuit.SetA(tA)
		circuit.SetMsg(tMsg)
		return circuit
	}
	return Random
}

func InputToCircuit[C Interface](circuit C, R []Curve.Point, S []*big.Int, A []Curve.Point, msg [][MLAR]byte) C {
	nval := len(A)
	tMsg := make([][MLAR]uints.U8, nval)
	tA := make([]Curve.PointCircuit, nval)
	tR := make([]Curve.PointCircuit, nval)
	tS := make([]Curve.ElementO, nval)
	for nv := 0; nv < nval; nv++ {
		for i := 0; i < MLAR; i++ {
			tMsg[nv][i] = uints.NewU8(msg[nv][i])
		}
		tA[nv] = Curve.PointToCircuit(A[nv])
		tR[nv] = Curve.PointToCircuit(R[nv])
		tS[nv] = Curve.BigIntToElementO(S[nv])
	}
	circuit.SetR(tR)
	circuit.SetS(tS)
	circuit.SetA(tA)
	circuit.SetMsg(tMsg)
	return circuit
}
