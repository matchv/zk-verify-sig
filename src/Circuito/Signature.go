package Circuito

import (
	Curve "ed25519/src/CurveEd25519"

	"math/big"

	csha3 "golang.org/x/crypto/sha3"
)

func BytesToSignature(sig [96]byte) (Curve.Point, *big.Int) {
	RX := big.NewInt(0).SetBytes(sig[:32])
	RY := big.NewInt(0).SetBytes(sig[32:64])
	S := big.NewInt(0).SetBytes(sig[64:96])
	return Curve.Point{X: RX, Y: RY}, S
}

func BytesToSignatureCircuit(sig [96]byte) (Curve.PointCircuit, Curve.ElementO) {
	RX := big.NewInt(0).SetBytes(sig[:32])
	RY := big.NewInt(0).SetBytes(sig[32:64])
	S := big.NewInt(0).SetBytes(sig[64:96])
	return Curve.PointToCircuit(Curve.Point{X: RX, Y: RY}), Curve.BigIntToElementO(S)
}

func SignatureToBytes(R Curve.Point, S *big.Int) [96]byte {
	var sig [96]byte
	R.X.FillBytes(sig[:32])
	R.Y.FillBytes(sig[32:64])
	S.FillBytes(sig[64:96])
	return sig
}

func BatchInputFromBytes(pk [][64]byte, sig [][96]byte) (R []Curve.Point, S []*big.Int, A []Curve.Point) {
	nval := len(pk)
	R = make([]Curve.Point, nval)
	S = make([]*big.Int, nval)
	A = make([]Curve.Point, nval)
	for i := 0; i < nval; i++ {
		A[i] = Curve.BytesToPoint(pk[i][:])
		R[i], S[i] = BytesToSignature(sig[i])
	}
	return
}

func Sign(msg [MLAR]byte, sk *big.Int) (signature [96]byte, pk [64]byte) {
	sha512 := csha3.New512()
	sha512.Write(sk.Bytes())
	H := sha512.Sum(nil)
	s := new(big.Int).SetBytes(H[0:32])
	A := Curve.IntToPoint(s)
	prefix := H[32:64]
	sha512.Reset()
	sha512.Write(prefix)
	sha512.Write(msg[:])
	r := new(big.Int).SetBytes(sha512.Sum(nil))
	r = r.Mul(r, big.NewInt(8))
	r = r.Mod(r, Curve.Ord)

	R := Curve.IntToPoint(r)

	sha512.Reset()
	sha512.Write(R.Bytes())
	sha512.Write(A.Bytes())
	sha512.Write(msg[:])
	k := new(big.Int).SetBytes(sha512.Sum(nil))
	k = k.Mod(k, Curve.Ord)

	S := big.NewInt(0).Add(big.NewInt(0).Mul(k, s), r)
	S.Mod(S, Curve.Ord)

	signature = SignatureToBytes(R, S)
	pk = [64]byte(A.Bytes())
	return
}

func SignBatch(msg [][MLAR]byte, sk []*big.Int) (signature [][96]byte, pk [][64]byte) {
	nval := len(msg)
	signature = make([][96]byte, nval)
	pk = make([][64]byte, nval)
	for i := 0; i < nval; i++ {
		signature[i], pk[i] = Sign(msg[i], sk[i])
	}
	return
}
