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

func init() {
	FieldBase, _ = big.NewInt(0).SetString("340282366920938463463374607431768211456", 10)
	solver.RegisterHint(HintProductO, HintInverseO, HintAddO, HintBitsElementO, HintElementToUint8O)
}

type ElementO struct {
	V [2]frontend.Variable
}

func NewElementO(a, b frontend.Variable) ElementO {
	return ElementO{[2]frontend.Variable{a, b}}
}

func BigIntToElementO(a *big.Int) ElementO {
	a = big.NewInt(0).Mod(a, Ord)
	return ElementO{[2]frontend.Variable{frontend.Variable(big.NewInt(0).Mod(a, FieldBase)), frontend.Variable(big.NewInt(0).Div(a, FieldBase))}}
}

func StringToElementO(a string) ElementO {
	b, _ := big.NewInt(0).SetString(a, 10)
	return BigIntToElementO(b)
}

func HintProductO(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	A := big.NewInt(0).Add(inputs[0], big.NewInt(0).Mul(inputs[1], FieldBase))
	B := big.NewInt(0).Add(inputs[2], big.NewInt(0).Mul(inputs[3], FieldBase))
	C := big.NewInt(0).Mul(A, B)
	Co := big.NewInt(0).Div(C, Ord)
	R := big.NewInt(0).Mod(C, Ord)
	result[0] = big.NewInt(0).Mod(R, FieldBase)
	result[1] = big.NewInt(0).Div(R, FieldBase)
	result[2] = big.NewInt(0).Set(Co)
	return nil
}

func ProdElementO(a, b ElementO, api frontend.API) ElementO {
	var res []frontend.Variable

	res, _ = api.Compiler().NewHint(HintProductO, 3, a.V[0], a.V[1], b.V[0], b.V[1])
	c := ElementO{[2]frontend.Variable{res[0], res[1]}}
	izq := api.Add(
		api.Mul(a.V[0], b.V[0]), api.Mul(a.V[1], b.V[0], FieldBaseC),
		api.Mul(a.V[0], b.V[1], FieldBaseC), api.Mul(a.V[1], b.V[1], FieldBaseC, FieldBaseC))
	der := api.Add(
		c.V[0], api.Mul(c.V[1], FieldBaseC), api.Mul(res[2], OrdC))
	api.AssertIsEqual(izq, der)
	return c
}

func ProdElementsO(a []ElementO, api frontend.API) ElementO {
	var res ElementO
	res = a[0]
	for i := 1; i < len(a); i++ {
		res = ProdElementO(res, a[i], api)
	}
	return res
}

func HintInverseO(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	A := big.NewInt(0).Add(inputs[0], big.NewInt(0).Mul(inputs[1], FieldBase))
	Res := big.NewInt(0).ModInverse(A, Ord)
	C := big.NewInt(0).Div(Res, Ord)
	R := big.NewInt(0).Mod(Res, Ord)
	result[0] = big.NewInt(0).Mod(R, FieldBase)
	result[1] = big.NewInt(0).Div(R, FieldBase)
	result[2] = big.NewInt(0).Set(C)
	return nil
}

func InverseElementO(b ElementO, api frontend.API) ElementO {
	res, _ := api.Compiler().NewHint(HintInverseO, 3, b.V[0], b.V[1])
	c := ElementO{[2]frontend.Variable{res[0], res[1]}}
	bc := ProdElementO(b, c, api)
	api.AssertIsEqual(bc.V[0], frontend.Variable(1))
	api.AssertIsEqual(bc.V[1], frontend.Variable(0))
	return c
}

func HintAddO(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	A := big.NewInt(0).Add(inputs[0], big.NewInt(0).Mul(inputs[1], FieldBase))
	B := big.NewInt(0).Add(inputs[2], big.NewInt(0).Mul(inputs[3], FieldBase))
	C := big.NewInt(0).Add(A, B)
	Co := big.NewInt(0).Div(C, Ord)
	R := big.NewInt(0).Mod(C, Ord)
	result[0] = big.NewInt(0).Mod(R, FieldBase)
	result[1] = big.NewInt(0).Div(R, FieldBase)
	result[2] = big.NewInt(0).Set(Co)
	return nil
}

func AddElementO(a, b ElementO, api frontend.API) ElementO {
	res, _ := api.Compiler().NewHint(HintAddO, 3, a.V[0], a.V[1], b.V[0], b.V[1])
	c := ElementO{[2]frontend.Variable{res[0], res[1]}}
	izq := api.Add(api.Add(a.V[0], b.V[0]), api.Mul(FieldBaseC, api.Add(a.V[1], b.V[1])))
	der := api.Add(c.V[0], api.Mul(FieldBaseC, c.V[1]), api.Mul(res[2], OrdC))
	api.AssertIsEqual(izq, der)
	return c
}

func AddElementsO(a []ElementO, api frontend.API) ElementO {
	var res ElementO
	res = a[0]
	for i := 1; i < len(a); i++ {
		res = AddElementO(res, a[i], api)
	}
	return res
}

func AssertEqualElementO(a, b ElementO, api frontend.API) {
	api.AssertIsEqual(a.V[0], b.V[0])
	api.AssertIsEqual(a.V[1], b.V[1])
}

func HintBitsElementO(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	x0 := big.NewInt(0).Set(inputs[0])
	x1 := big.NewInt(0).Set(inputs[1])
	for i := 0; i < 128; i++ {
		result[i].Mod(x0, big.NewInt(2))
		x0.Div(x0, big.NewInt(2))
	}
	for i := 128; i < 253; i++ {
		result[i].Mod(x1, big.NewInt(2))
		x1.Div(x1, big.NewInt(2))
	}

	return nil
}

func BitsElementO(a ElementO, api frontend.API) []frontend.Variable {
	var res []frontend.Variable
	//api.Println("a : ", a.V[0], a.V[1])
	res, _ = api.Compiler().NewHint(HintBitsElementO, 253, a.V[0], a.V[1])
	izq := frontend.Variable(0)

	for i := 0; i < 253; i++ {
		izq = api.Select(res[i], api.Add(izq, frontend.Variable(big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(i)), nil))), izq)
		//base = api.Mul(base, frontend.Variable(2))
	}

	//api.Println(res...)
	//api.Println(a.V[0], a.V[1])
	der := api.Add(a.V[0], api.Mul(a.V[1], FieldBaseC))
	api.AssertIsEqual(izq, der)
	return res
}

func HintElementToUint8O(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	x := big.NewInt(0).Add(big.NewInt(0).Mul(inputs[1], FieldBase), inputs[0])
	//fmt.Println(FieldBase)
	for i := 0; i < 32; i++ {
		result[31-i].Mod(x, big.NewInt(256))
		x.Div(x, big.NewInt(256))
	}
	return nil
}

func ElementToUint8O(a ElementO, api frontend.API, uapi *uints.BinaryField[uints.U64]) []uints.U8 {
	temp, _ := api.Compiler().NewHint(HintElementToUint8O, 32, a.V[0], a.V[1])
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
