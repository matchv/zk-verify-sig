package Curve

import (

	//"github.com/consensys/gnark/backend"
	//"github.com/consensys/gnark/frontend"

	//"github.com/rs/zerolog"

	//"github.com/consensys/gnark/std/algebra/fields_bls12377"

	//"github.com/consensys/gnark-crypto/ecc/bls12-377/fptower"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

var FieldBase *big.Int
var FieldBaseC = "340282366920938463463374607431768211456"

func init() {
	FieldBase, _ = big.NewInt(0).SetString("340282366920938463463374607431768211456", 10)
}

type Element struct {
	V [2]frontend.Variable
}

func BigIntToElement(a *big.Int) Element {
	return Element{[2]frontend.Variable{frontend.Variable(big.NewInt(0).Mod(a, FieldBase)), frontend.Variable(big.NewInt(0).Div(a, FieldBase))}}
}

func StringToElement(a string) Element {
	b, _ := big.NewInt(0).SetString(a, 10)
	return BigIntToElement(b)
}

func HintProduct(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
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

func ProdElement(a, b Element, api frontend.API) Element {
	var res []frontend.Variable
	res, _ = api.Compiler().NewHint(HintProduct, 3, a.V[0], a.V[1], b.V[0], b.V[1])
	c := Element{[2]frontend.Variable{res[0], res[1]}}
	izq := api.Add(
		api.Mul(a.V[0], b.V[0]), api.Mul(a.V[1], b.V[0], FieldBaseC),
		api.Mul(a.V[0], b.V[1], FieldBaseC), api.Mul(a.V[1], b.V[1], FieldBaseC, FieldBaseC))
	der := api.Add(
		c.V[0], api.Mul(c.V[1], FieldBaseC), api.Mul(res[2], QC))
	api.AssertIsEqual(izq, der)
	return c
}

func ProdElements(a []Element, api frontend.API) Element {
	var res Element
	res = a[0]
	for i := 1; i < len(a); i++ {
		res = ProdElement(res, a[i], api)
	}
	return res
}

func HintInverse(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	A := big.NewInt(0).Add(inputs[0], big.NewInt(0).Mul(inputs[1], FieldBase))
	Res := big.NewInt(0).ModInverse(A, Q)
	C := big.NewInt(0).Div(Res, Q)
	R := big.NewInt(0).Mod(Res, Q)
	result[0] = big.NewInt(0).Mod(R, FieldBase)
	result[1] = big.NewInt(0).Div(R, FieldBase)
	result[2] = big.NewInt(0).Set(C)
	return nil
}

func InverseElement(b Element, api frontend.API) Element {
	res, _ := api.Compiler().NewHint(HintInverse, 3, b.V[0], b.V[1])
	c := Element{[2]frontend.Variable{res[0], res[1]}}
	bc := ProdElement(b, c, api)
	api.AssertIsEqual(bc.V[0], frontend.Variable(1))
	api.AssertIsEqual(bc.V[1], frontend.Variable(0))
	return c
}

func HintAdd(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
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

func AddElement(a, b Element, api frontend.API) Element {
	res, _ := api.Compiler().NewHint(HintAdd, 3, a.V[0], a.V[1], b.V[0], b.V[1])
	c := Element{[2]frontend.Variable{res[0], res[1]}}
	izq := api.Add(api.Add(a.V[0], b.V[0]), api.Mul(FieldBaseC, api.Add(a.V[1], b.V[1])))
	der := api.Add(c.V[0], api.Mul(FieldBaseC, c.V[1]), api.Mul(res[2], QC))
	api.AssertIsEqual(izq, der)
	return c
}

func AddElements(a []Element, api frontend.API) Element {
	var res Element
	res = a[0]
	for i := 1; i < len(a); i++ {
		res = AddElement(res, a[i], api)
	}
	return res
}

func AssertEqualElement(a, b Element, api frontend.API) {
	api.AssertIsEqual(a.V[0], b.V[0])
	api.AssertIsEqual(a.V[1], b.V[1])
}

func HintBitsElement(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
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

func BitsElement(a Element, api frontend.API) []frontend.Variable {
	var res []frontend.Variable
	//api.Println("a : ", a.V[0], a.V[1])
	res, _ = api.Compiler().NewHint(HintBitsElement, 256, a.V[0], a.V[1])
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

func ElementToUint8(a Element, api frontend.API, uapi *uints.BinaryField[uints.U64]) []uints.U8 {
	res := make([]uints.U8, 32)
	bits := BitsElement(a, api)
	for i := 0; i < 32; i++ {
		X := frontend.Variable(0)
		base := frontend.Variable(1)
		for j := i * 8; j < (i+1)*8; j++ {
			X = api.Select(bits[j], api.Add(X, base), X)
			base = api.Mul(base, frontend.Variable(2))
		}
		res[31-i] = uapi.ByteValueOf(X)
		//res[i].Val = X
	}
	return res
}
