package Circuito

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	//"github.com/rs/zerolog"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"

	crand "crypto/rand"
	"testing"

	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	td "github.com/consensys/gnark/std/algebra/native/twistededwards"
	sha3 "golang.org/x/crypto/sha3"

	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func IntToPoint(x *big.Int) tbn254.PointAffine {
	var lbX, lbY fr.Element
	var p tbn254.PointAffine = tbn254.NewPointAffine(lbX, lbY)
	p = *p.ScalarMultiplication(&p, x)
	return p
}

func ToSlice(b [32]byte) []byte {
	r := make([]byte, 32)
	copy(r, b[:])
	return r
}

func PointFromAffine(p *tbn254.PointAffine) td.Point {
	var r td.Point
	r.X = frontend.Variable(p.X)
	r.Y = frontend.Variable(p.X)
	return r
}

func AssertOnCurve(x fr.Element, y fr.Element, assert *test.Assert) {
	x2 := fr.Element{}
	x2.Mul(&x, &x)
	y2 := fr.Element{}
	y2.Mul(&y, &y)
	ladoIzq := fr.Element{}
	fra := fr.NewElement(a.Uint64())
	frd := fr.NewElement(d.Uint64())
	ladoIzq.Mul(&x2, &fra)
	ladoIzq.Add(&ladoIzq, &y2)

	ladoDer := fr.Element{}
	ladoDer.Mul(&x2, &y2)
	ladoDer.Mul(&ladoDer, &frd)
	ladoDer.Add(&ladoDer, &fr.Element{1})

	assert.Equal(ladoIzq, ladoDer)
}

func ElementoToBigInt(e fr.Element) *big.Int {
	return new(big.Int).SetBytes(ToSlice(e.Bytes()))
}

func TestIntToPoint_1(t *testing.T) {
	assert := test.NewAssert(t)
	P := IntToPoint(big.NewInt(1))
	fmt.Println(bX.Cmp(fr.Modulus()))
	fmt.Println(bY.Cmp(fr.Modulus()))
	AssertOnCurve(P.X, P.Y, assert)
}

func TestRandomAC(t *testing.T) {
	for NT := 10; NT > 0; NT-- {
		assert := test.NewAssert(t)
		mod := bn254.ID.ScalarField()
		var tR [NVAL]td.Point
		var tS [NVAL]frontend.Variable
		var tA [NVAL]td.Point
		var tMsg [NVAL]frontend.Variable

		for nv := 0; nv < NVAL; nv++ {
			sk, _ := crand.Int(crand.Reader, mod)
			m, _ := crand.Int(crand.Reader, mod)
			tMsg[nv] = frontend.Variable(m)

			sha512 := sha3.New512()
			sha512.Write(sk.Bytes())
			H := sha512.Sum(nil)
			s := new(big.Int).SetBytes(H[0:32])
			A := IntToPoint(s)
			tA[nv] = PointFromAffine(&A)

			prefix := H[32:64]
			sha512.Reset()
			sha512.Write(prefix)
			sha512.Write(m.Bytes())
			r := new(big.Int).SetBytes(sha512.Sum(nil))

			R := IntToPoint(r)
			tR[nv] = PointFromAffine(&R)
			fmt.Print("R: ")
			AssertOnCurve(R.X, R.Y, assert)
			sha512.Reset()
			sha512.Write(ToSlice(R.Bytes()))
			sha512.Write(ToSlice(A.Bytes()))
			sha512.Write(m.Bytes())
			k := new(big.Int).SetBytes(sha512.Sum(nil))
			S := big.NewInt(0).Add(big.NewInt(0).Mul(k, s), r)
			S.Mod(S, ord)
			tS[nv] = frontend.Variable(S)
		}
		assert.NoError(test.IsSolved(&Circuit{}, &Circuit{
			R:   tR,
			S:   tS,
			A:   tA,
			Msg: tMsg,
		}, ecc.BN254.ScalarField()))
	}
}

func TestGenOnCurve(t *testing.T) {
	X2 := big.NewInt(0).Exp(bX, big.NewInt(2), nil)
	Y2 := big.NewInt(0).Exp(bY, big.NewInt(2), nil)
	ladoIzq := big.NewInt(0).Add(big.NewInt(0).Mul(X2, a), Y2)
	ladoDer := big.NewInt(0).Add(big.NewInt(1), big.NewInt(0).Mul(
		big.NewInt(0).Mul(d, X2), Y2))
	ladoIzq.Mod(ladoIzq, q)
	ladoDer.Mod(ladoDer, q)
	fmt.Println(ladoIzq)
	fmt.Println(ladoDer)
	fmt.Println(q)
	if ladoIzq.Cmp(ladoDer) != 0 {
		t.Errorf("El punto base no está en la curva.")
	}
}

func TestGenOnCurveAlt(t *testing.T) {
	X2 := big.NewInt(0).Exp(bu, big.NewInt(2), q)
	Y2 := big.NewInt(0).Exp(bv, big.NewInt(2), q)
	ladoIzq := Y2
	ladoDer := big.NewInt(0).Add(big.NewInt(486662), bu)
	ladoDer.Mul(ladoDer, X2)
	ladoDer.Add(ladoDer, bu)

	ladoIzq.Mod(ladoIzq, q)
	ladoDer.Mod(ladoDer, q)
	fmt.Println(ladoIzq)
	fmt.Println(ladoDer)
	fmt.Println(q)
	if ladoIzq.Cmp(ladoDer) != 0 {
		t.Errorf("El punto base no está en la curva.")
	}
}
