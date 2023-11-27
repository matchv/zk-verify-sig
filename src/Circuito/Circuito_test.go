package Circuito

import (
	Curve "ed25519/src/CurveEd25519"
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
	td "github.com/consensys/gnark/std/algebra/native/twistededwards"
	sha3 "golang.org/x/crypto/sha3"

	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func TestIntToPoint_1(t *testing.T) {
	P := Curve.IntToPoint(big.NewInt(1))
	fmt.Println(Curve.BX.Cmp(fr.Modulus()))
	fmt.Println(Curve.BY.Cmp(fr.Modulus()))
	if Curve.OnCurve(P.X, P.Y) == false {
		t.Errorf("P is not on curve")
	}
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
			A := Curve.IntToPoint(s)
			tA[nv] = Curve.PointFromAffine(&A)

			prefix := H[32:64]
			sha512.Reset()
			sha512.Write(prefix)
			sha512.Write(m.Bytes())
			r := new(big.Int).SetBytes(sha512.Sum(nil))

			R := Curve.IntToPoint(r)
			assert.Equal(Curve.OnCurve(R.X, R.Y), true, "R is not on curve")
			tR[nv] = Curve.PointFromAffine(&R)
			fmt.Print("R: ")
			//AssertOnCurve(R.X, R.Y, assert)
			sha512.Reset()
			sha512.Write(R.Bytes())
			sha512.Write(A.Bytes())
			sha512.Write(m.Bytes())
			k := new(big.Int).SetBytes(sha512.Sum(nil))
			S := big.NewInt(0).Add(big.NewInt(0).Mul(k, s), r)
			S.Mod(S, Curve.Ord)
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
