package Circuito

import (
	Curve "ed25519/src/CurveEd25519"

	"github.com/consensys/gnark-crypto/ecc"

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	//"github.com/rs/zerolog"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"

	crand "crypto/rand"
	"testing"

	sha3 "golang.org/x/crypto/sha3"

	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
	"math/big"
)

/*func TestIntToPoint_1(t *testing.T) {
	P := Curve.IntToPoint(big.NewInt(1))
	fmt.Println(Curve.BX.Cmp(fr.Modulus()))
	fmt.Println(Curve.BY.Cmp(fr.Modulus()))
	if Curve.OnCurve(P.X, P.Y) == false {
		t.Errorf("P is not on curve")
	}
}*/

func TestRandomAC(t *testing.T) {
	maximo := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(256), nil)
	for NT := 2; NT > 0; NT-- {
		assert := test.NewAssert(t)
		//mod := bn254.ID.ScalarField()
		var tR [NVAL]Curve.PointCircuit
		var tS [NVAL]Curve.Element      //frontend.Variable
		var tA [NVAL]Curve.PointCircuit //td.Point
		var tMsg [NVAL]Curve.Element    // frontend.Variable

		for nv := 0; nv < NVAL; nv++ {
			sk, _ := crand.Int(crand.Reader, Curve.Q)
			m, _ := crand.Int(crand.Reader, maximo)
			tMsg[nv] = Curve.BigIntToElement(m, maximo)

			sha512 := sha3.New512()
			sha512.Write(sk.Bytes())
			H := sha512.Sum(nil)
			s := new(big.Int).SetBytes(H[0:32])
			A := Curve.IntToPoint(s)
			assert.Equal(Curve.OnCurve(A.X, A.Y), true, "A is not on curve")
			tA[nv] = Curve.PointToCircuit(A)

			prefix := H[32:64]
			sha512.Reset()
			sha512.Write(prefix)
			sha512.Write(m.FillBytes(make([]byte, 32)))
			r := new(big.Int).SetBytes(sha512.Sum(nil))
			r = r.Mod(r, Curve.Ord)

			R := Curve.IntToPoint(r)
			assert.Equal(Curve.OnCurve(R.X, R.Y), true, "R is not on curve")
			tR[nv] = Curve.PointToCircuit(R)
			//fmt.Print("R: ")
			//AssertOnCurve(R.X, R.Y, assert)
			sha512.Reset()
			sha512.Write(R.Bytes())
			sha512.Write(A.Bytes())
			sha512.Write(m.FillBytes(make([]byte, 32)))
			k := new(big.Int).SetBytes(sha512.Sum(nil))
			k = k.Mod(k, Curve.Ord)
			//fmt.Println(sha512.Sum(nil))
			//fmt.Println(k)

			S := big.NewInt(0).Add(big.NewInt(0).Mul(k, s), r)
			S.Mod(S, Curve.Ord)
			tS[nv] = Curve.BigIntToElement(S, Curve.Ord)

			/*fmt.Println("Out Circuit ")
			fmt.Println("A: ", A.X, " ", A.Y)
			fmt.Println("R: ", R.X, " ", R.Y)
			fmt.Println("K: ", k)
			DER := Curve.MulByScalar(Curve.MulByScalar(A, k), big.NewInt(8))
			DER = Curve.Add(DER, Curve.MulByScalar(R, big.NewInt(8)))
			fmt.Println("DER: ", DER.X, " ", DER.Y)

			Bl := Curve.IntToPoint(big.NewInt(0).Mul(S, big.NewInt(8)))
			fmt.Println("Bl: ", Bl.X, " ", Bl.Y)
			*/
		}
		assert.NoError(test.IsSolved(&Circuit{}, &Circuit{
			R:   tR,
			S:   tS,
			A:   tA,
			Msg: tMsg,
		}, ecc.BN254.ScalarField()))
	}
}
