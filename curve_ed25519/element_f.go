package curve_ed25519

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

var FieldModulus *big.Int
var FieldModulusC = "115792089237316195423570985008687907853269984665640564039457584007913129639936"

func init() {
	FieldBase, _ = big.NewInt(0).SetString("340282366920938463463374607431768211456", 10)
	FieldModulus, _ = big.NewInt(0).SetString(FieldModulusC, 10)
	solver.RegisterHint(HintProductF, HintInverseF, HintAddF, HintBitsElementF, HintElementToUint8F)
}

type ElementF struct {
	V [2]frontend.Variable
}

func BigIntToElementF(a *big.Int) ElementF {
	a = big.NewInt(0).Mod(a, FieldModulus)
	return ElementF{[2]frontend.Variable{frontend.Variable(big.NewInt(0).Mod(a, FieldBase)), frontend.Variable(big.NewInt(0).Div(a, FieldBase))}}
}

func StringToElementF(a string) ElementF {
	b, _ := big.NewInt(0).SetString(a, 10)
	return BigIntToElementF(b)
}

func HintProductF(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	A := big.NewInt(0).Add(inputs[0], big.NewInt(0).Mul(inputs[1], FieldBase))
	B := big.NewInt(0).Add(inputs[2], big.NewInt(0).Mul(inputs[3], FieldBase))
	C := big.NewInt(0).Mul(A, B)
	Co := big.NewInt(0).Div(C, FieldModulus)
	R := big.NewInt(0).Mod(C, FieldModulus)
	result[0] = big.NewInt(0).Mod(R, FieldBase)
	result[1] = big.NewInt(0).Div(R, FieldBase)
	result[2] = big.NewInt(0).Set(Co)
	return nil
}

func ProdElementF(a, b ElementF, api frontend.API) ElementF {
	var res []frontend.Variable

	res, _ = api.Compiler().NewHint(HintProductF, 3, a.V[0], a.V[1], b.V[0], b.V[1])
	c := ElementF{[2]frontend.Variable{res[0], res[1]}}
	izq := api.Add(
		api.Mul(a.V[0], b.V[0]), api.Mul(a.V[1], b.V[0], FieldBaseC),
		api.Mul(a.V[0], b.V[1], FieldBaseC), api.Mul(a.V[1], b.V[1], FieldBaseC, FieldBaseC))
	der := api.Add(
		c.V[0], api.Mul(c.V[1], FieldBaseC), api.Mul(res[2], FieldModulus))
	api.AssertIsEqual(izq, der)
	return c
}

func ProdElementsF(a []ElementF, api frontend.API) ElementF {
	var res ElementF
	res = a[0]
	for i := 1; i < len(a); i++ {
		res = ProdElementF(res, a[i], api)
	}
	return res
}

func HintInverseF(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	A := big.NewInt(0).Add(inputs[0], big.NewInt(0).Mul(inputs[1], FieldBase))
	Res := big.NewInt(0).ModInverse(A, FieldModulus)
	C := big.NewInt(0).Div(Res, FieldModulus)
	R := big.NewInt(0).Mod(Res, FieldModulus)
	result[0] = big.NewInt(0).Mod(R, FieldBase)
	result[1] = big.NewInt(0).Div(R, FieldBase)
	result[2] = big.NewInt(0).Set(C)
	return nil
}

func InverseElementF(b ElementF, api frontend.API) ElementF {
	res, _ := api.Compiler().NewHint(HintInverseF, 3, b.V[0], b.V[1])
	c := ElementF{[2]frontend.Variable{res[0], res[1]}}
	bc := ProdElementF(b, c, api)
	api.AssertIsEqual(bc.V[0], frontend.Variable(1))
	api.AssertIsEqual(bc.V[1], frontend.Variable(0))
	return c
}

func HintAddF(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	A := big.NewInt(0).Add(inputs[0], big.NewInt(0).Mul(inputs[1], FieldBase))
	B := big.NewInt(0).Add(inputs[2], big.NewInt(0).Mul(inputs[3], FieldBase))
	C := big.NewInt(0).Add(A, B)
	Co := big.NewInt(0).Div(C, FieldModulus)
	R := big.NewInt(0).Mod(C, FieldModulus)
	result[0] = big.NewInt(0).Mod(R, FieldBase)
	result[1] = big.NewInt(0).Div(R, FieldBase)
	result[2] = big.NewInt(0).Set(Co)
	return nil
}

func AddElementF(a, b ElementF, api frontend.API) ElementF {
	res, _ := api.Compiler().NewHint(HintAddF, 3, a.V[0], a.V[1], b.V[0], b.V[1])
	c := ElementF{[2]frontend.Variable{res[0], res[1]}}
	izq := api.Add(api.Add(a.V[0], b.V[0]), api.Mul(FieldBaseC, api.Add(a.V[1], b.V[1])))
	der := api.Add(c.V[0], api.Mul(FieldBaseC, c.V[1]), api.Mul(res[2], FieldModulusC))
	api.AssertIsEqual(izq, der)
	return c
}

func AddElementsF(a []ElementF, api frontend.API) ElementF {
	var res ElementF
	res = a[0]
	for i := 1; i < len(a); i++ {
		res = AddElementF(res, a[i], api)
	}
	return res
}

func AssertEqualElementF(a, b ElementF, api frontend.API) {
	api.AssertIsEqual(a.V[0], b.V[0])
	api.AssertIsEqual(a.V[1], b.V[1])
}

func HintBitsElementF(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
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

func BitsElementF(a ElementF, api frontend.API) []frontend.Variable {
	var res []frontend.Variable
	//api.Println("a : ", a.V[0], a.V[1])
	res, _ = api.Compiler().NewHint(HintBitsElementF, 256, a.V[0], a.V[1])
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

func HintElementToUint8F(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	x := big.NewInt(0).Add(big.NewInt(0).Mul(inputs[1], FieldBase), inputs[0])
	//fmt.Println(FieldBase)
	for i := 0; i < 32; i++ {
		result[31-i].Mod(x, big.NewInt(256))
		x.Div(x, big.NewInt(256))
	}
	return nil
}

func ElementToUint8F(a ElementF, api frontend.API, uapi *uints.BinaryField[uints.U64]) []uints.U8 {
	temp, _ := api.Compiler().NewHint(HintElementToUint8F, 32, a.V[0], a.V[1])
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
