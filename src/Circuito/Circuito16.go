package Circuito

import (
	Curve "ed25519/src/CurveEd25519"

	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"

	crand "crypto/rand"

	csha3 "golang.org/x/crypto/sha3"
)

// 5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14

type Circuit16 struct {
	R   [16]Curve.PointCircuit `gnark:",public"`
	S   [16]Curve.ElementO     `gnark:",public"`
	A   [16]Curve.PointCircuit `gnark:",public"`
	Msg [16][MLAR]uints.U8     `gnark:",public"`
	//Msg [NVAL]Curve.ElementF     `gnark:",public"`
}

// 5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14

func (circuit *Circuit16) Define(api frontend.API) error {

	//	api.Println("CURVE Q ", Curve.Q)
	for i := 0; i < 16; i++ {

		Curve.OnCurveCircuit(circuit.R[i], api)
		Curve.OnCurveCircuit(circuit.A[i], api)
		sha512, _ := sha3.New512(api)
		uapi, _ := uints.New[uints.U64](api)

		sha512.Write(Curve.ElementToUint8Q(circuit.R[i].X, api, uapi))
		sha512.Write(Curve.ElementToUint8Q(circuit.R[i].Y, api, uapi))
		sha512.Write(Curve.ElementToUint8Q(circuit.A[i].X, api, uapi))
		sha512.Write(Curve.ElementToUint8Q(circuit.A[i].Y, api, uapi))
		sha512.Write(circuit.Msg[i][:])

		temp := sha512.Sum()
		k := Curve.HashToValueO(uapi, api, temp)

		B := Curve.MulByScalarCircuitWithPows(Curve.GetBaseCircuit(), circuit.S[i], Curve.GetBaseCircuitPows(), api)

		A := Curve.MulByScalarCircuit(circuit.A[i], Curve.ProdElementO(k, Curve.StringToElementO("8"), api), api)
		R := circuit.R[i]
		for j := 0; j < 3; j++ {
			R = Curve.AddCircuit(R, R, api)
			B = Curve.AddCircuit(B, B, api)
		}
		A = Curve.AddCircuit(A, R, api)

		Curve.AssertEqualElementQ(A.X, B.X, api)
		Curve.AssertEqualElementQ(A.Y, B.Y, api)

	}
	return nil
}

func Random16() *Circuit16 {
	circuit := new(Circuit16)
	for nv := 0; nv < 16; nv++ {
		sk, _ := crand.Int(crand.Reader, Curve.Q)
		var m [MLAR]byte
		crand.Read(m[:])
		for i := 0; i < MLAR; i++ {
			circuit.Msg[nv][i] = uints.NewU8(m[i])
		}
		sha512 := csha3.New512()
		sha512.Write(sk.Bytes())
		H := sha512.Sum(nil)
		s := new(big.Int).SetBytes(H[0:32])
		A := Curve.IntToPoint(s)
		circuit.A[nv] = Curve.PointToCircuit(A)

		prefix := H[32:64]
		sha512.Reset()
		sha512.Write(prefix)
		sha512.Write(m[:])
		r := new(big.Int).SetBytes(sha512.Sum(nil))
		r = r.Mul(r, big.NewInt(8))
		r = r.Mod(r, Curve.Ord)

		R := Curve.IntToPoint(r)
		circuit.R[nv] = Curve.PointToCircuit(R)
		sha512.Reset()
		sha512.Write(R.Bytes())
		sha512.Write(A.Bytes())
		sha512.Write(m[:])
		k := new(big.Int).SetBytes(sha512.Sum(nil))
		k = k.Mod(k, Curve.Ord)

		S := big.NewInt(0).Add(big.NewInt(0).Mul(k, s), r)
		S.Mod(S, Curve.Ord)
		circuit.S[nv] = Curve.BigIntToElementO(S)
	}
	return circuit
}
