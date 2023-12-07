package curve_ed25519

import (

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"

	//"github.com/rs/zerolog"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"
	crand "crypto/rand"
	"fmt"
	"testing"

	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
	"math/big"
)

func TestDouble(t *testing.T) {
	//fmt.Println(Q)
	Op1 := Add(BASE, BASE)
	Op2 := MulByScalar(BASE, big.NewInt(2))
	if Op1.X.Cmp(Op2.X) != 0 || Op1.Y.Cmp(Op2.Y) != 0 {
		fmt.Println(Op1.X, " vs ", Op2.X)
		fmt.Println(Op1.Y, " vs ", Op2.Y)

		t.Errorf("BASE+BASE != BASE * 2")
	}
}

func TestProdN(t *testing.T) {
	for nt := 0; nt < 30; nt++ {
		S_, _ := crand.Int(crand.Reader, big.NewInt(10000))
		S := int(S_.Int64())

		Op1 := MulByScalar(BASE, S_)
		Op2 := BASE
		for s := 1; s < S; s++ {
			Op2 = Add(Op2, BASE)
		}
		if Op1.X.Cmp(Op2.X) != 0 || Op1.Y.Cmp(Op2.Y) != 0 {
			fmt.Println(Op1.X, " vs ", Op2.X)
			fmt.Println(Op1.Y, " vs ", Op2.Y)

			t.Errorf("BASE+BASE != BASE * 2")
		}
	}
}

func TestDistributive(t *testing.T) {
	for nt := 0; nt < 100; nt++ {
		S1, _ := crand.Int(crand.Reader, Q)
		S2, _ := crand.Int(crand.Reader, Q)
		Sum := big.NewInt(0).Add(S1, S2)
		//Sum = Sum.Mod(Sum, Q)
		Op1 := Add(MulByScalar(BASE, S1), MulByScalar(BASE, S2))
		Op2 := MulByScalar(BASE, Sum)

		ps := []Point{Op1, Op2}
		for ind, p := range ps {
			if p.X.Cmp(Op1.X) > 0 || p.Y.Cmp(Op1.Y) > 0 {
				fmt.Println(Op1.X, " , ", Op1.Y)
				fmt.Println(Op2.X, " , ", Op2.Y)

				t.Errorf("Error in %d", ind)
				return
			}
		}
	}
}

func TestAsociativeProduct(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		SA, _ := crand.Int(crand.Reader, Q)
		SB, _ := crand.Int(crand.Reader, Q)

		Op1 := MulByScalar(MulByScalar(BASE, SA), SB)
		Op2 := MulByScalar(BASE, big.NewInt(0).Mul(SA, SB))

		if Op1.X.Cmp(Op2.X) != 0 || Op1.Y.Cmp(Op2.Y) != 0 {
			fmt.Println(Op1.X, " vs ", Op2.X)
			fmt.Println(Op1.Y, " vs ", Op2.Y)

			t.Errorf("Error in Asociative Product")
		}
	}
}

func TestCommutativeProduct(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		SA, _ := crand.Int(crand.Reader, Q)
		SB, _ := crand.Int(crand.Reader, Q)

		Op1 := MulByScalar(MulByScalar(BASE, SA), SB)
		Op2 := MulByScalar(MulByScalar(BASE, SB), SA)

		if Op1.X.Cmp(Op2.X) != 0 || Op1.Y.Cmp(Op2.Y) != 0 {
			fmt.Println(Op1.X, " vs ", Op2.X)
			fmt.Println(Op1.Y, " vs ", Op2.Y)

			t.Errorf("Error in Commutative Product")
		}
	}
}

func TestAsociativeSum(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		SA, _ := crand.Int(crand.Reader, Q)
		SB, _ := crand.Int(crand.Reader, Q)
		SC, _ := crand.Int(crand.Reader, Q)

		A := MulByScalar(BASE, SA)
		B := MulByScalar(BASE, SB)
		C := MulByScalar(BASE, SC)

		ABC := Add(Add(A, B), C)
		ACB := Add(Add(A, C), B)

		if ABC.X.Cmp(ACB.X) != 0 || ABC.Y.Cmp(ACB.Y) != 0 {
			t.Errorf("Error in Asociative Sum")
		}
	}
}

func TestCommutativeSum(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		SA, _ := crand.Int(crand.Reader, Q)
		SB, _ := crand.Int(crand.Reader, Q)

		A := MulByScalar(BASE, SA)
		B := MulByScalar(BASE, SB)

		AB := Add(A, B)
		BA := Add(B, A)

		if AB.X.Cmp(BA.X) != 0 || AB.Y.Cmp(BA.Y) != 0 {
			t.Errorf("Error in Commutative Sum")
		}
	}
}

func TestGenOnCurve(t *testing.T) {
	X2 := big.NewInt(0).Exp(BX, big.NewInt(2), nil)
	Y2 := big.NewInt(0).Exp(BY, big.NewInt(2), nil)
	ladoIzq := big.NewInt(0).Add(big.NewInt(0).Mul(X2, A), Y2)
	ladoDer := big.NewInt(0).Add(big.NewInt(1), big.NewInt(0).Mul(
		big.NewInt(0).Mul(D, X2), Y2))
	ladoIzq.Mod(ladoIzq, Q)
	ladoDer.Mod(ladoDer, Q)
	/*fmt.Println(ladoIzq)
	fmt.Println(ladoDer)
	fmt.Println(Q)*/
	if ladoIzq.Cmp(ladoDer) != 0 {
		t.Errorf("El punto base no está en la curva.")
	}

	if OnCurve(BX, BY) == false {
		t.Errorf("El punto base no está en la curva.")
	}
}

func TestGenOnCurveAlt(t *testing.T) {
	U2 := big.NewInt(0).Exp(BU, big.NewInt(2), Q)
	V2 := big.NewInt(0).Exp(BV, big.NewInt(2), Q)
	ladoIzq := V2
	ladoDer := big.NewInt(0).Add(big.NewInt(486662), BU)
	ladoDer.Mul(ladoDer, U2)
	ladoDer.Add(ladoDer, BU)

	ladoIzq.Mod(ladoIzq, Q)
	ladoDer.Mod(ladoDer, Q)
	/*fmt.Println(ladoIzq)
	fmt.Println(ladoDer)
	fmt.Println(Q)*/
	if ladoIzq.Cmp(ladoDer) != 0 {
		t.Errorf("El punto base no está en la curva.")
	}
}

func TestProductInCurve(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		S, _ := crand.Int(crand.Reader, Q)
		A := MulByScalar(BASE, S)

		if OnCurve(A.X, A.Y) == false {
			t.Errorf("Error in Product in Curve")
			return
		}

	}
}

func TestAddInCurve(t *testing.T) {
	for nt := 0; nt < 10; nt++ {
		SA, _ := crand.Int(crand.Reader, Q)
		SB, _ := crand.Int(crand.Reader, Q)

		A := MulByScalar(BASE, SA)
		B := MulByScalar(BASE, SB)

		AB := Add(A, B)

		if OnCurve(AB.X, AB.Y) == false {
			t.Errorf("Error in Add in Curve")
		}
	}
}

func TestCompressForm(t *testing.T) {
	for nt := 0; nt < 100; nt++ {
		S, _ := crand.Int(crand.Reader, Q)
		A := MulByScalar(BASE, S)
		if OnCurve(A.X, A.Y) == false {
			t.Errorf("Error in Compress Form")
		}
		compress := A.CompressForm()
		Ap := CompressToPoint(compress)
		if Ap.X.Cmp(A.X) != 0 || Ap.Y.Cmp(A.Y) != 0 {
			t.Errorf(Ap.X.String() + " vs " + A.X.String() + " , " + Ap.Y.String() + " vs " + A.Y.String())
			t.Errorf("Error in Compress Form")
		}
	}
}
