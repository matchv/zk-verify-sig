package signature_verifier

import (
	"ed25519/curve_ed25519"
	"math/big"

	crand "crypto/rand"

	"github.com/consensys/gnark/frontend"
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
	nval := len(A)
	tMsg := make([][MLAR]uints.U8, nval)
	tA := make([][32]uints.U8, nval)
	tR := make([][32]uints.U8, nval)
	tS := make([]curve_ed25519.ElementO, nval)
	for nv := 0; nv < nval; nv++ {
		for i := 0; i < MLAR; i++ {
			tMsg[nv][i] = uints.NewU8(msg[nv][i])
		}
		tA[nv] = [32]uints.U8(A[nv].CompressFormCircuit())
		tR[nv] = [32]uints.U8(R[nv].CompressFormCircuit())
		tS[nv] = curve_ed25519.BigIntToElementO(S[nv])
	}
	circuit.SetR(tR)
	circuit.SetS(tS)
	circuit.SetA(tA)
	circuit.SetMsg(tMsg)
	return circuit
}
