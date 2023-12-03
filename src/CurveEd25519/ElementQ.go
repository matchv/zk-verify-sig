package Curve

import (

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"

	//"github.com/rs/zerolog"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"

	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"

	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func init() {
	FieldBase, _ = big.NewInt(0).SetString("340282366920938463463374607431768211456", 10)
	solver.RegisterHint(HintProductQ, HintDivQ, HintInverseQ, HintAddQ, HintSubQ, HintBitsElementQ, HintElementToUint8Q)
}

type ElementQ struct {
	V [2]frontend.Variable
}

func BigIntToElementQ(a *big.Int) ElementQ {
	a = big.NewInt(0).Mod(a, Q)
	return ElementQ{[2]frontend.Variable{frontend.Variable(big.NewInt(0).Mod(a, FieldBase)), frontend.Variable(big.NewInt(0).Div(a, FieldBase))}}
}

func StringToElementQ(a string) ElementQ {
	b, _ := big.NewInt(0).SetString(a, 10)
	return BigIntToElementQ(b)
}

func HintProductQ(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	A := big.NewInt(0).Add(inputs[0], big.NewInt(0).Mul(inputs[1], FieldBase))
	B := big.NewInt(0).Add(inputs[2], big.NewInt(0).Mul(inputs[3], FieldBase))
	C := big.NewInt(0).Mul(A, B)
	Co := big.NewInt(0).Div(C, Q)
	R := big.NewInt(0).Mod(C, Q)
	result[0] = big.NewInt(0).Mod(R, FieldBase)
	result[1] = big.NewInt(0).Div(R, FieldBase)
	result[2] = big.NewInt(0).Set(Co)
	return nil
}

func ProdElementQ(a, b ElementQ, api frontend.API) ElementQ {
	var res []frontend.Variable

	res, _ = api.Compiler().NewHint(HintProductQ, 3, a.V[0], a.V[1], b.V[0], b.V[1])
	c := ElementQ{[2]frontend.Variable{res[0], res[1]}}
	izq := api.Add(
		api.Mul(a.V[0], b.V[0]), api.Mul(a.V[1], b.V[0], FieldBaseC),
		api.Mul(a.V[0], b.V[1], FieldBaseC), api.Mul(a.V[1], b.V[1], FieldBaseC, FieldBaseC))
	//izq := api.Add(
	//		api.Mul(a.V[0], b.V[0]), api.Mul(FieldBaseC,
	//			api.Add(api.Mul(a.V[1], b.V[0]), api.Mul(a.V[0], b.V[1])), api.Mul(FieldBaseC, a.V[1], b.V[1])))
	der := api.Add(
		c.V[0], api.Mul(c.V[1], FieldBaseC), api.Mul(res[2], QC))
	api.AssertIsEqual(izq, der)
	return c
}

func HintDivQ(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	a := big.NewInt(0).Add(inputs[0], big.NewInt(0).Mul(inputs[1], FieldBase))
	b := big.NewInt(0).Add(inputs[2], big.NewInt(0).Mul(inputs[3], FieldBase))
	c := big.NewInt(0).ModInverse(b, Q)
	d := big.NewInt(0).Mul(a, c)
	d = big.NewInt(0).Mod(d, Q)
	x := big.NewInt(0).Div(big.NewInt(0).Sub(big.NewInt(0).Mul(d, b), a), Q)
	/// d * b = a + Q * x

	result[0] = big.NewInt(0).Mod(d, FieldBase)
	result[1] = big.NewInt(0).Div(d, FieldBase)
	result[2] = big.NewInt(0).Mod(x, FieldBase)
	result[3] = big.NewInt(0).Div(x, FieldBase)
	return nil
}

func DivElementQ(a, b ElementQ, api frontend.API) ElementQ {
	var res []frontend.Variable

	res, _ = api.Compiler().NewHint(HintDivQ, 4, a.V[0], a.V[1], b.V[0], b.V[1])
	c := ElementQ{[2]frontend.Variable{res[0], res[1]}}
	va := api.Add(a.V[0], api.Mul(FieldBaseC, a.V[1]))
	vb := api.Add(b.V[0], api.Mul(FieldBaseC, b.V[1]))
	vd := api.Add(c.V[0], api.Mul(FieldBaseC, c.V[1]))
	vx := api.Add(res[2], api.Mul(FieldBaseC, res[3]))

	api.AssertIsEqual(api.Mul(vd, vb), api.Add(va, api.Mul(QC, vx)))
	return c
}

func ProdElementsQ(a []ElementQ, api frontend.API) ElementQ {
	var res ElementQ
	res = a[0]
	for i := 1; i < len(a); i++ {
		res = ProdElementQ(res, a[i], api)
	}
	return res
}

func HintInverseQ(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	A := big.NewInt(0).Add(inputs[0], big.NewInt(0).Mul(inputs[1], FieldBase))
	Res := big.NewInt(0).ModInverse(A, Q)
	C := big.NewInt(0).Div(Res, Q)
	R := big.NewInt(0).Mod(Res, Q)
	result[0] = big.NewInt(0).Mod(R, FieldBase)
	result[1] = big.NewInt(0).Div(R, FieldBase)
	result[2] = big.NewInt(0).Set(C)
	return nil
}

func InverseElementQ(b ElementQ, api frontend.API) ElementQ {
	res, _ := api.Compiler().NewHint(HintInverseQ, 3, b.V[0], b.V[1])
	c := ElementQ{[2]frontend.Variable{res[0], res[1]}}
	bc := ProdElementQ(b, c, api)
	api.AssertIsEqual(bc.V[0], frontend.Variable(1))
	api.AssertIsEqual(bc.V[1], frontend.Variable(0))
	return c
}

func HintAddQ(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	A := big.NewInt(0).Add(inputs[0], big.NewInt(0).Mul(inputs[1], FieldBase))
	B := big.NewInt(0).Add(inputs[2], big.NewInt(0).Mul(inputs[3], FieldBase))
	C := big.NewInt(0).Add(A, B)
	Co := big.NewInt(0).Div(C, Q)
	R := big.NewInt(0).Mod(C, Q)
	result[0] = big.NewInt(0).Mod(R, FieldBase)
	result[1] = big.NewInt(0).Div(R, FieldBase)
	result[2] = big.NewInt(0).Set(Co)
	return nil
}

func AddElementQ(a, b ElementQ, api frontend.API) ElementQ {
	res, _ := api.Compiler().NewHint(HintAddQ, 3, a.V[0], a.V[1], b.V[0], b.V[1])
	c := ElementQ{[2]frontend.Variable{res[0], res[1]}}
	izq := api.Add(a.V[0], b.V[0], api.Mul(FieldBaseC, api.Add(a.V[1], b.V[1])))
	der := api.Add(c.V[0], api.Mul(FieldBaseC, c.V[1]), api.Mul(res[2], QC))
	api.AssertIsEqual(izq, der)
	return c
}

func HintSubQ(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	A := big.NewInt(0).Add(inputs[0], big.NewInt(0).Mul(inputs[1], FieldBase))
	B := big.NewInt(0).Add(inputs[2], big.NewInt(0).Mul(inputs[3], FieldBase))
	C := big.NewInt(0).Sub(A, B)
	//C = big.NewInt(0).Add(C, Q)
	/*fmt.Println(A)
	fmt.Println(B)
	fmt.Println(C)*/
	Co := big.NewInt(0).Div(C, Q)
	R := big.NewInt(0).Mod(C, Q)
	result[0] = big.NewInt(0).Mod(R, FieldBase)
	result[1] = big.NewInt(0).Div(R, FieldBase)
	result[2] = big.NewInt(0).Set(Co)
	return nil
}

func SubElementQ(a, b ElementQ, api frontend.API) ElementQ {
	res, _ := api.Compiler().NewHint(HintSubQ, 3, a.V[0], a.V[1], b.V[0], b.V[1])
	c := ElementQ{[2]frontend.Variable{res[0], res[1]}}
	va := api.Add(a.V[0], api.Mul(FieldBaseC, a.V[1]))
	vb := api.Add(b.V[0], api.Mul(FieldBaseC, b.V[1]))
	vc := api.Add(c.V[0], api.Mul(FieldBaseC, c.V[1]), api.Mul(res[2], QC))

	api.AssertIsEqual(api.Sub(va, vb), vc)
	return c
}

func AddElementsQ(a []ElementQ, api frontend.API) ElementQ {
	var res ElementQ
	res = a[0]
	for i := 1; i < len(a); i++ {
		res = AddElementQ(res, a[i], api)
	}
	return res
}

func AssertEqualElementQ(a, b ElementQ, api frontend.API) {
	api.AssertIsEqual(a.V[0], b.V[0])
	api.AssertIsEqual(a.V[1], b.V[1])
}

func HintBitsElementQ(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	x0 := big.NewInt(0).Set(inputs[0])
	x1 := big.NewInt(0).Set(inputs[1])
	for i := 0; i < 128; i++ {
		result[i].Mod(x0, big.NewInt(2))
		x0.Div(x0, big.NewInt(2))
	}
	for i := 128; i < 256; i++ {
		result[i].Mod(x1, big.NewInt(2))
		x1.Div(x1, big.NewInt(2))
	}

	return nil
}

func BitsElementQ(a ElementQ, api frontend.API) []frontend.Variable {
	var res []frontend.Variable
	//api.Println("a : ", a.V[0], a.V[1])
	res, _ = api.Compiler().NewHint(HintBitsElementQ, 256, a.V[0], a.V[1])
	base := frontend.Variable(1)
	izq := frontend.Variable(0)

	for i := 0; i < 256; i++ {
		izq = api.Select(res[i], api.Add(izq, base), izq)
		base = api.Mul(base, frontend.Variable(2))
	}

	//api.Println(res...)
	//api.Println(a.V[0], a.V[1])
	der := api.Add(a.V[0], api.Mul(a.V[1], FieldBaseC))
	api.AssertIsEqual(izq, der)
	return res
}

func HintElementToUint8Q(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	x := big.NewInt(0).Add(big.NewInt(0).Mul(inputs[1], FieldBase), inputs[0])
	//fmt.Println(FieldBase)
	for i := 0; i < 32; i++ {
		result[31-i].Mod(x, big.NewInt(256))
		x.Div(x, big.NewInt(256))
	}
	return nil
}

func ElementToUint8Q(a ElementQ, api frontend.API, uapi *uints.BinaryField[uints.U64]) []uints.U8 {
	temp, _ := api.Compiler().NewHint(HintElementToUint8Q, 32, a.V[0], a.V[1])
	var res []uints.U8 = make([]uints.U8, 32)
	check := frontend.Variable(0)
	//for i := 31; i >= 0; i-- {
	for i := 0; i < 32; i++ {
		res[i] = uapi.ByteValueOf(temp[i])
		check = api.Add(api.Mul(check, frontend.Variable("256")), temp[i])
	}
	api.AssertIsEqual(check, api.Add(a.V[0], api.Mul(a.V[1], FieldBaseC)))
	return res
}
