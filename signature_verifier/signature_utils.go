package signature_verifier

import (
	"ed25519/curve_ed25519"
	"math/big"

	csha3 "golang.org/x/crypto/sha3"
)

func BytesToSignature(sig [96]byte) (curve_ed25519.Point, *big.Int) {
	RX := big.NewInt(0).SetBytes(sig[:32])
	RY := big.NewInt(0).SetBytes(sig[32:64])
	S := big.NewInt(0).SetBytes(sig[64:96])
	return curve_ed25519.Point{X: RX, Y: RY}, S
}

func BachBytesToSignature(sig [][96]byte) (R []curve_ed25519.Point, S []*big.Int) {
	nval := len(sig)
	R = make([]curve_ed25519.Point, nval)
	S = make([]*big.Int, nval)
	for i := 0; i < nval; i++ {
		R[i], S[i] = BytesToSignature(sig[i])
	}
	return
}

func BytesToSignatureCircuit(sig [96]byte) (curve_ed25519.PointCircuit, curve_ed25519.ElementO) {
	RX := big.NewInt(0).SetBytes(sig[:32])
	RY := big.NewInt(0).SetBytes(sig[32:64])
	S := big.NewInt(0).SetBytes(sig[64:96])
	return curve_ed25519.PointToCircuit(curve_ed25519.Point{X: RX, Y: RY}), curve_ed25519.BigIntToElementO(S)
}

func SignatureToBytes(R curve_ed25519.Point, S *big.Int) [96]byte {
	var sig [96]byte
	R.X.FillBytes(sig[:32])
	R.Y.FillBytes(sig[32:64])
	S.FillBytes(sig[64:96])
	return sig
}

func BatchInputFromBytes(pk [][64]byte, sig [][96]byte) (R []curve_ed25519.Point, S []*big.Int, A []curve_ed25519.Point) {
	nval := len(pk)
	R = make([]curve_ed25519.Point, nval)
	S = make([]*big.Int, nval)
	A = make([]curve_ed25519.Point, nval)
	for i := 0; i < nval; i++ {
		A[i] = curve_ed25519.BytesToPoint(pk[i][:])
		R[i], S[i] = BytesToSignature(sig[i])
	}
	return
}

func Sign(msg [MLAR]byte, sk *big.Int) (signature [96]byte, pk [64]byte) {
	sha512 := csha3.New512()
	sha512.Write(sk.Bytes())
	H := sha512.Sum(nil)
	s := new(big.Int).SetBytes(H[0:32])
	A := curve_ed25519.IntToPoint(s)
	prefix := H[32:64]
	sha512.Reset()
	sha512.Write(prefix)
	sha512.Write(msg[:])
	r := new(big.Int).SetBytes(sha512.Sum(nil))
	r = r.Mul(r, big.NewInt(8))
	r = r.Mod(r, curve_ed25519.Ord)

	R := curve_ed25519.IntToPoint(r)

	sha512.Reset()
	sha512.Write(R.Bytes())
	sha512.Write(A.Bytes())
	sha512.Write(msg[:])
	k := new(big.Int).SetBytes(sha512.Sum(nil))
	k = k.Mod(k, curve_ed25519.Ord)

	S := big.NewInt(0).Add(big.NewInt(0).Mul(k, s), r)
	S.Mod(S, curve_ed25519.Ord)

	signature = SignatureToBytes(R, S)
	pk = [64]byte(A.Bytes())
	return
}

func BatchSign(msg [][MLAR]byte, sk []*big.Int) (signature [][96]byte, pk [][64]byte) {
	nval := len(msg)
	signature = make([][96]byte, nval)
	pk = make([][64]byte, nval)
	for i := 0; i < nval; i++ {
		signature[i], pk[i] = Sign(msg[i], sk[i])
	}
	return
}

func SignatureToCompress(R curve_ed25519.Point, S *big.Int) [64]byte {
	var sig [64]byte
	temp := R.CompressForm()
	copy(sig[:32], temp[:])
	S.FillBytes(sig[32:64])
	for i := 32; i < 64; i++ {
		j := 63 - i + 32
		sig[i], sig[j] = sig[j], sig[i]
	}
	return sig
}

func BatchSignatureToCompress(R []curve_ed25519.Point, S []*big.Int) (sig [][64]byte) {
	nval := len(R)
	sig = make([][64]byte, nval)
	for i := 0; i < nval; i++ {
		sig[i] = SignatureToCompress(R[i], S[i])
	}
	return
}

func CompressToSignature(sig [64]byte) (R curve_ed25519.Point, S *big.Int) {
	temp := [32]byte{}
	copy(temp[:], sig[:32])
	R = curve_ed25519.CompressToPoint(temp)
	for i := 32; i < 64; i++ {
		j := 63 - i + 32
		sig[i], sig[j] = sig[j], sig[i]
	}
	S = big.NewInt(0).SetBytes(sig[32:64])
	return
}

func BatchCompressToSignature(sig [][64]byte) (R []curve_ed25519.Point, S []*big.Int) {
	nval := len(sig)
	R = make([]curve_ed25519.Point, nval)
	S = make([]*big.Int, nval)
	for i := 0; i < nval; i++ {
		R[i], S[i] = CompressToSignature(sig[i])
	}
	return
}

func InputToCompress(R curve_ed25519.Point, S *big.Int, A curve_ed25519.Point) (sign [64]byte, pk [32]byte) {
	sign = SignatureToCompress(R, S)
	pk = [32]byte(A.CompressForm())
	return
}

func BatchInputToCompress(R []curve_ed25519.Point, S []*big.Int, A []curve_ed25519.Point) (sign [][64]byte, pk [][32]byte) {
	nval := len(R)
	sign = make([][64]byte, nval)
	pk = make([][32]byte, nval)
	for i := 0; i < nval; i++ {
		sign[i], pk[i] = InputToCompress(R[i], S[i], A[i])
	}
	return
}

// Decompresses a signature
func CompressToInput(sig [64]byte, pk [32]byte) (R curve_ed25519.Point, S *big.Int, A curve_ed25519.Point) {
	R, S = CompressToSignature(sig)
	A = curve_ed25519.CompressToPoint(pk)
	return
}

// Decompresses a batch of (signature, public keys)
func BatchCompressToInput(sig [][64]byte, pk [][32]byte) (R []curve_ed25519.Point, S []*big.Int, A []curve_ed25519.Point) {
	nval := len(sig)
	R = make([]curve_ed25519.Point, nval)
	S = make([]*big.Int, nval)
	A = make([]curve_ed25519.Point, nval)
	for i := 0; i < nval; i++ {
		R[i], S[i], A[i] = CompressToInput(sig[i], pk[i])
	}
	return
}

func SignCompress(msg [MLAR]byte, sk *big.Int) (signature [64]byte, pk [32]byte) {
	sha512 := csha3.New512()
	sha512.Write(sk.Bytes())
	H := sha512.Sum(nil)
	s := new(big.Int).SetBytes(H[0:32])
	A := curve_ed25519.IntToPoint(s)
	prefix := H[32:64]
	sha512.Reset()
	sha512.Write(prefix)
	sha512.Write(msg[:])
	r := new(big.Int).SetBytes(sha512.Sum(nil))
	r = r.Mul(r, big.NewInt(8))
	r = r.Mod(r, curve_ed25519.Ord)

	R := curve_ed25519.IntToPoint(r)

	sha512.Reset()
	sha512.Write(R.Bytes())
	sha512.Write(A.Bytes())
	sha512.Write(msg[:])
	k := new(big.Int).SetBytes(sha512.Sum(nil))
	k = k.Mod(k, curve_ed25519.Ord)

	S := big.NewInt(0).Add(big.NewInt(0).Mul(k, s), r)
	S.Mod(S, curve_ed25519.Ord)

	signature = SignatureToCompress(R, S)
	pk = [32]byte(A.CompressForm())
	return
}

func BatchSignCompress(msg [][MLAR]byte, sk []*big.Int) (signature [][64]byte, pk [][32]byte) {
	nval := len(msg)
	signature = make([][64]byte, nval)
	pk = make([][32]byte, nval)
	for i := 0; i < nval; i++ {
		signature[i], pk[i] = SignCompress(msg[i], sk[i])
	}
	return
}
