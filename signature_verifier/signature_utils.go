package signature_verifier

import (
	"ed25519/curve_ed25519"
	"math/big"

	csha2 "crypto/sha512"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	//csha3 "golang.org/x/crypto/sha2"
)

func InvertArray[T any](in []T) (out []T) {
	tam := len(in)
	out = make([]T, tam)
	for i := 0; i < tam; i++ {
		out[i] = in[tam-1-i]
	}
	return
}

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

func Campling(x []byte) (res *big.Int) {
	w := make([]byte, 32)
	copy(w[:], x[:])
	w[0] &= 248
	w[31] &= 63
	w[31] |= 64
	res = new(big.Int).SetBytes(InvertArray(w[:]))
	res = res.Mod(res, curve_ed25519.Ord)
	return
}

func Sign(msg [MLAR]byte, sk []byte) (signature [96]byte, pk [64]byte) {
	sha512 := csha2.New()
	sha512.Write(sk)
	H := sha512.Sum(nil)
	s := Campling(H[0:32])
	A := curve_ed25519.IntToPoint(s)
	prefix := H[32:64]
	sha512 = csha2.New()
	sha512.Write(prefix)
	sha512.Write(msg[:])
	r := big.NewInt(0).SetBytes(InvertArray(sha512.Sum(nil)))
	r = r.Mod(r, curve_ed25519.Ord)

	R := curve_ed25519.IntToPoint(r)

	sha512 = csha2.New()
	sha512.Write(R.CompressForm())
	sha512.Write(A.CompressForm())
	sha512.Write(msg[:])
	k := big.NewInt(0).SetBytes(InvertArray(sha512.Sum(nil)))
	k = k.Mod(k, curve_ed25519.Ord)

	S := big.NewInt(0).Add(big.NewInt(0).Mul(k, s), r)
	S.Mod(S, curve_ed25519.Ord)

	signature = SignatureToBytes(R, S)
	pk = [64]byte(A.Bytes())
	return
}

func BatchSign(msg [][MLAR]byte, sk [][]byte) (signature [][96]byte, pk [][64]byte) {
	nval := len(msg)
	signature = make([][96]byte, nval)
	pk = make([][64]byte, nval)
	for i := 0; i < nval; i++ {
		signature[i], pk[i] = Sign(msg[i], sk[i])
	}
	return
}

func SignatureToCompress(R curve_ed25519.Point, S *big.Int) []byte {
	sig := make([]byte, 64)
	temp := R.CompressForm()
	copy(sig[:32], temp[:])
	temp2 := make([]byte, 32)
	temp2 = S.FillBytes(temp2)
	for i := 32; i < 64; i++ {
		j := 63 - i
		sig[i] = temp2[j]
	}
	return sig
}

func BatchSignatureToCompress(R []curve_ed25519.Point, S []*big.Int) (sig [][]byte) {
	nval := len(R)
	sig = make([][]byte, nval)
	for i := 0; i < nval; i++ {
		sig[i] = SignatureToCompress(R[i], S[i])
	}
	return
}

func CompressToSignature(sig []byte) (R curve_ed25519.Point, S *big.Int) {
	temp := make([]byte, 32)
	copy(temp[:], sig[:32])
	R = curve_ed25519.CompressToPoint(temp)
	S = big.NewInt(0).SetBytes(InvertArray(sig[32:64]))
	return
}

func BatchCompressToSignature(sig [][]byte) (R []curve_ed25519.Point, S []*big.Int) {
	nval := len(sig)
	R = make([]curve_ed25519.Point, nval)
	S = make([]*big.Int, nval)
	for i := 0; i < nval; i++ {
		R[i], S[i] = CompressToSignature(sig[i])
	}
	return
}

func InputToCompress(R curve_ed25519.Point, S *big.Int, A curve_ed25519.Point) (sign []byte, pk []byte) {
	sign = SignatureToCompress(R, S)
	pk = (A.CompressForm())
	return
}

func BatchInputToCompress(R []curve_ed25519.Point, S []*big.Int, A []curve_ed25519.Point) (sign [][]byte, pk [][]byte) {
	nval := len(R)
	sign = make([][]byte, nval)
	pk = make([][]byte, nval)
	for i := 0; i < nval; i++ {
		sign[i], pk[i] = InputToCompress(R[i], S[i], A[i])
	}
	return
}

// Decompresses a signature
func CompressToInput(sig []byte, pk []byte) (R curve_ed25519.Point, S *big.Int, A curve_ed25519.Point) {
	R, S = CompressToSignature(sig)
	A = curve_ed25519.CompressToPoint(pk)
	return
}

// Decompresses a batch of (signature, public keys)
func BatchCompressToInput(sig [][]byte, pk [][]byte) (R []curve_ed25519.Point, S []*big.Int, A []curve_ed25519.Point) {
	nval := len(sig)
	R = make([]curve_ed25519.Point, nval)
	S = make([]*big.Int, nval)
	A = make([]curve_ed25519.Point, nval)
	for i := 0; i < nval; i++ {
		R[i], S[i], A[i] = CompressToInput(sig[i], pk[i])
	}
	return
}

func SignCompress(msg [MLAR]byte, sk []byte) (signature []byte, pk []byte) {
	sha512 := csha2.New()
	sha512.Write(sk)
	H := sha512.Sum(nil)
	s := Campling(H[0:32])
	A := curve_ed25519.IntToPoint(s)
	prefix := H[32:64]
	sha512 = csha2.New()
	sha512.Write(prefix)
	sha512.Write(msg[:])
	r := new(big.Int).SetBytes(InvertArray(sha512.Sum(nil)))
	r = r.Mod(r, curve_ed25519.Ord)

	R := curve_ed25519.IntToPoint(r)

	sha512 = csha2.New()
	sha512.Write(R.CompressForm())
	sha512.Write(A.CompressForm())
	sha512.Write(msg[:])
	k := new(big.Int).SetBytes(InvertArray(sha512.Sum(nil)))
	k = k.Mod(k, curve_ed25519.Ord)

	S := big.NewInt(0).Add(big.NewInt(0).Mul(k, s), r)
	S.Mod(S, curve_ed25519.Ord)

	signature = SignatureToCompress(R, S)
	pk = (A.CompressForm())
	return
}

func BatchSignCompress(msg [][MLAR]byte, sk [][]byte) (signature [][]byte, pk [][]byte) {
	nval := len(msg)
	signature = make([][]byte, nval)
	pk = make([][]byte, nval)
	for i := 0; i < nval; i++ {
		signature[i], pk[i] = SignCompress(msg[i], sk[i])
	}
	return
}

func init() {
	solver.RegisterHint(SHA2_512_MODORD_HINT)
	solver.RegisterHint(SHA2_512_HINT)
}

func SHA2_512_MODORD_HINT(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	sha512 := csha2.New()
	in := make([]byte, len(inputs))
	for i := 0; i < len(inputs); i++ {
		in[i] = byte(inputs[i].Uint64())
	}
	sha512.Write(in)
	temp := InvertArray(sha512.Sum(nil))
	X := big.NewInt(0).SetBytes(temp)
	X = X.Mod(X, curve_ed25519.Ord)
	result[0] = big.NewInt(0).Mod(X, curve_ed25519.FieldBase)
	result[1] = big.NewInt(0).Div(X, curve_ed25519.FieldBase)
	return nil
}

func SHA2_512_MODORDWithHints(api frontend.API, inputs []frontend.Variable) curve_ed25519.ElementO {

	res, _ := api.Compiler().NewHint(SHA2_512_MODORD_HINT, 2, inputs[:]...)
	return curve_ed25519.ElementO{V: [2]frontend.Variable{res[0], res[1]}}
}

func SHA2_512_HINT(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	sha512 := csha2.New()
	in := make([]byte, len(inputs))
	for i := 0; i < len(inputs); i++ {
		in[i] = byte(inputs[i].Uint64())
	}
	sha512.Write(in)
	temp := sha512.Sum(nil)
	for i := 0; i < 64; i++ {
		result[i] = big.NewInt(0).SetUint64(uint64(temp[i]))
	}
	return nil
}

func SHA2_512WithHints(uapi *uints.BinaryField[uints.U64], api frontend.API, inputs []frontend.Variable) [64]uints.U8 {
	temp, _ := api.Compiler().NewHint(SHA2_512_HINT, 64, inputs[:]...)
	var res [64]uints.U8
	for i := 0; i < 64; i++ {
		res[i] = uapi.ByteValueOf(temp[i])
	}
	return res
}

func BigIntToUint8(a *big.Int) []uints.U8 {
	temp := make([]byte, 32)
	temp = InvertArray(a.FillBytes(temp))
	res := make([]uints.U8, 32)
	for i := 0; i < 32; i++ {
		res[i] = uints.NewU8(temp[i])
	}
	return res
}

func ConcatMultipleSlices[T any](slices ...[]T) []T {
	var totalLen int

	for _, s := range slices {
		totalLen += len(s)
	}

	result := make([]T, totalLen)

	var i int

	for _, s := range slices {
		i += copy(result[i:], s)
	}

	return result
}

func ArrayU8toU64Circuit(uapi *uints.BinaryField[uints.U64], a []uints.U8) []uints.U64 {
	n := len(a)
	n2 := (n + (8-n%8)%8)
	temp := make([]uints.U8, n2)
	copy(temp[:], a[:])
	res := make([]uints.U64, n2/8)
	for i := 0; i < n2/8; i++ {
		res[i] = uapi.PackMSB(temp[(8 * i):(8*i + 8)]...)
	}
	return res
}
