package curve_ed25519

import (
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	td "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/math/uints"

	"math/big"

	"github.com/consensys/gnark/frontend"
)

func init() {
	//fmt.Println("Iniciando...")
	var temp *big.Int = new(big.Int)
	Q.Exp(big.NewInt(2), big.NewInt(255), nil)
	Q.Sub(Q, big.NewInt(19))

	A.Sub(Q, big.NewInt(1))
	D.SetString("37095705934669439343138083508754565189542113879843219016388785533085940283555", 10)
	temp.SetString("27742317777372353535851937790883648493", 10)
	Ord.Exp(big.NewInt(2), big.NewInt(252), nil)
	Ord.Add(Ord, temp)
	Cofactor.SetInt64(8)

	BU.Set(big.NewInt(9))
	BV.SetString("20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9", 16)

	BX.SetString(BXC, 10)
	BY.SetString(BYC, 10)

	/*BX.SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202", 10)
	//BX.Mul(BU, big.NewInt(0).ModInverse(BV, Q))
	BY.Mul(big.NewInt(1).Add(big.NewInt(-1), BU),
		big.NewInt(0).ModInverse(big.NewInt(0).Add(big.NewInt(1), BU), Q))

	BX.Mod(BX, Q)
	BY.Mod(BY, Q)*/
	BASE = Point{BX, BY}
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
	var res []frontend.Variable
	res, _ = api.Compiler().NewHint(HintModulus, 2, a, QC)
	api.AssertIsEqual(api.Add(api.Mul(res[1], QC), res[0]), a)
	return res[0]
}

func UnsafeByteToElement[T ElementF | ElementQ | ElementO](input []uints.U8, New func(a, b frontend.Variable) T, api frontend.API) T {
	a := frontend.Variable(0)
	b := frontend.Variable(0)
	for i := 15; i >= 0; i-- {
		a = api.Add(api.Mul(a, frontend.Variable(256)), frontend.Variable(input[i].Val))
		b = api.Add(api.Mul(b, frontend.Variable(256)), frontend.Variable(input[i+16].Val))
	}
	return New(a, b)
}
