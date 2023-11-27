package Curve

import (

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"

	//"github.com/rs/zerolog"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"

	"fmt"

	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	td "github.com/consensys/gnark/std/algebra/native/twistededwards"

	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func init() {
	fmt.Println("Iniciando...")
	var temp *big.Int = new(big.Int)
	Q.Exp(big.NewInt(2), big.NewInt(255), nil)
	Q.Sub(Q, big.NewInt(19))

	A.SetUint64(486664)
	D.SetUint64(486660)
	temp.SetString("27742317777372353535851937790883648493", 10)
	Ord.Exp(big.NewInt(2), big.NewInt(252), nil)
	Ord.Add(Ord, temp)
	Cofactor.SetInt64(8)

	BU.Set(big.NewInt(9))
	BV.SetString("5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14", 16)

	BX.Mul(BU, big.NewInt(0).ModInverse(BV, Q))
	BY.Mul(big.NewInt(1).Add(big.NewInt(-1), BU),
		big.NewInt(0).ModInverse(big.NewInt(0).Add(big.NewInt(1), BU), Q))

	BX.Mod(BX, Q)
	BY.Mod(BY, Q)
	BASE = Point{BX, BY}

	/*fmt.Println("Q :: ", Q)
	fmt.Println("A :: ", A)
	fmt.Println("D :: ", D)
	fmt.Println("Ord :: ", Ord)
	fmt.Println("Cofactor :: ", Cofactor)
	fmt.Println("BX :: ", BX)
	fmt.Println("BY :: ", BY)
	fmt.Println("BU :: ", BU)
	fmt.Println("BV :: ", BV)*/

	/*AC = frontend.Variable(A)
	DC = frontend.Variable(D)
	QC = frontend.Variable(Q)
	OrdC = frontend.Variable(Ord)
	CofactorC = frontend.Variable(Cofactor)
	BXC = frontend.Variable(BX)
	BYC = frontend.Variable(BY)
	BUC = frontend.Variable(BU)
	BVC = frontend.Variable(BV)
	BASEC = PointCircuit{BXC, BYC}*/
	fmt.Println(QC)
}
func IntToPoint(x *big.Int) Point {
	return MulByScalar(BASE, x)
}

func ToSlice(b [32]byte) []byte {
	r := make([]byte, 32)
	copy(r, b[:])
	return r
}

func PointFromAffine(p *Point) td.Point {
	var r td.Point
	r.X = frontend.Variable(p.X)
	r.Y = frontend.Variable(p.X)
	return r
}

func ElementoToBigInt(e fr.Element) *big.Int {
	return new(big.Int).SetBytes(ToSlice(e.Bytes()))
}

func HintModulus(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	result[0].Mod(inputs[0], inputs[1])
	result[1].Div(inputs[0], inputs[1])
	return nil
}

func ModCircuit(a frontend.Variable, api frontend.API) frontend.Variable {
	//c := api.Div(a, QC)
	//res := api.Sub(a, api.Mul(c, QC))
	var res []frontend.Variable
	res, _ = api.Compiler().NewHint(HintModulus, 2, a, QC)
	api.AssertIsEqual(api.Add(api.Mul(res[1], QC), res[0]), a)
	return res[0]
}
