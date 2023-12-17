package curve_ed25519

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const QC = "57896044618658097711785492504343953926634992332820282019728792003956564819949"
const AC = "57896044618658097711785492504343953926634992332820282019728792003956564819948"
const DC = "37095705934669439343138083508754565189542113879843219016388785533085940283555"
const CofactorC = "8"
const OrdC = "7237005577332262213973186563042994240857116359379907606001950938285454250989"
const BXC = "15112221349535400772501151409588531511454012693041857206046113283949847762202"
const BYC = "46316835694926478169428394003475163141307993866256225615783033603165251855960"
const BUC = "9"
const BVC = "14781619447589544791020593568409986887264606134616475288964881837755586237401"

type PointCircuit struct {
	X, Y ElementQ
}

func PointToCircuit(p Point) PointCircuit {
	return PointCircuit{X: BigIntToElementQ(p.X), Y: BigIntToElementQ(p.Y)}
}

func GetBaseCircuit() PointCircuit {
	return PointCircuit{StringToElementQ(BXC), StringToElementQ(BYC)}
}

func GetBaseCircuitPows() [253]PointCircuit {
	var res [253]PointCircuit
	res[0] = GetBaseCircuit()
	for i := 1; i < 253; i++ {
		res[i] = PointToCircuit(IntToPoint(big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(i)), nil)))
	}
	return res
}

// var BASEC
func AddCircuit(p1, p2 PointCircuit, api frontend.API) PointCircuit {
	YY := ProdElementQ(p1.Y, p2.Y, api)
	XX := ProdElementQ(p1.X, p2.X, api)
	Z := ProdElementQ(XX, YY, api)
	ZD := ProdElementQ(Z, StringToElementQ(DC), api)
	X := DivElementQ(
		//SubElementQ(ProdElementQ(AddElementQ(p1.X, p1.Y, api), AddElementQ(p2.X, p2.Y, api), api), AddElementQ(XX, YY, api), api),
		AddElementQ(ProdElementQ(p1.X, p2.Y, api), ProdElementQ(p1.Y, p2.X, api), api),
		AddElementQ(BigIntToElementQ(big.NewInt(1)), ZD, api), api)

	Y := DivElementQ(AddElementQ(YY, XX, api), SubElementQ(BigIntToElementQ(big.NewInt(1)), ZD, api), api)

	return PointCircuit{X, Y}
}

func MulByScalarCircuit(p PointCircuit, s ElementO, api frontend.API) PointCircuit {
	//exp := BitsElement(AddElement(StringToElement("57896044618658097711785492504343953926634992332820282019728792003956564819948", OrdC), s, api), api)
	exp := BitsElementO(s, api)
	res := PointCircuit{StringToElementQ("0"), StringToElementQ("1")}
	for i := 0; i < 253; i++ {
		temp := AddCircuit(res, p, api)

		res.X.V[0] = api.Select(exp[i], temp.X.V[0], res.X.V[0])
		res.X.V[1] = api.Select(exp[i], temp.X.V[1], res.X.V[1])
		res.Y.V[0] = api.Select(exp[i], temp.Y.V[0], res.Y.V[0])
		res.Y.V[1] = api.Select(exp[i], temp.Y.V[1], res.Y.V[1])

		p = AddCircuit(p, p, api)
	}
	return res
}

func MulByScalarCircuitWithPows(p PointCircuit, s ElementO, pows [253]PointCircuit, api frontend.API) PointCircuit {
	//exp := BitsElement(AddElement(StringToElement("57896044618658097711785492504343953926634992332820282019728792003956564819948", OrdC), s, api), api)
	exp := BitsElementO(s, api)
	res := PointCircuit{StringToElementQ("0"), StringToElementQ("1")}
	for i := 0; i < 253; i++ {
		temp := AddCircuit(res, pows[i], api)
		res.X.V[0] = api.Select(exp[i], temp.X.V[0], res.X.V[0])
		res.X.V[1] = api.Select(exp[i], temp.X.V[1], res.X.V[1])
		res.Y.V[0] = api.Select(exp[i], temp.Y.V[0], res.Y.V[0])
		res.Y.V[1] = api.Select(exp[i], temp.Y.V[1], res.Y.V[1])
	}
	return res
}

func OnCurveCircuit(p PointCircuit, api frontend.API) {
	X2 := ProdElementQ(p.X, p.X, api)
	Y2 := ProdElementQ(p.Y, p.Y, api)
	izq := ProdElementQ(StringToElementQ(AC), X2, api)
	izq = AddElementQ(izq, Y2, api)

	der := ProdElementQ(StringToElementQ(DC), ProdElementQ(X2, Y2, api), api)
	der = AddElementQ(der, BigIntToElementQ(big.NewInt(1)), api)

	AssertEqualElementQ(izq, der, api)
}

func HashToValueQ(uapi *uints.BinaryField[uints.U64], api frontend.API, hash []uints.U8) ElementQ {
	res := StringToElementQ("0")
	//	api.Println("RES 0 : ", res.V[0], " ", res.V[1])
	for i := len(hash) - 1; i >= 0; i-- {
		res = ProdElementQ(res, StringToElementQ("256"), api)
		res = AddElementQ(res, ElementQ{[2]frontend.Variable{hash[i].Val, frontend.Variable(0)}}, api)
		//	api.Println("RES ", res.V[0], " ", res.V[1])
		//res = api.Mul(res, frontend.Variable(256))
		//res = api.Add(res, hash[i].Val)
	}

	return res
}

func HashToValueO(api frontend.API, hash []uints.U8) ElementO {
	res := StringToElementO("0")
	//	api.Println("RES 0 : ", res.V[0], " ", res.V[1])
	for i := len(hash) - 1; i >= 0; i-- {
		res = ProdElementO(res, StringToElementO("256"), api)
		res = AddElementO(res, ElementO{[2]frontend.Variable{hash[i].Val, frontend.Variable(0)}}, api)
		//	api.Println("RES ", res.V[0], " ", res.V[1])
		//res = api.Mul(res, frontend.Variable(256))
		//res = api.Add(res, hash[i].Val)
	}

	return res
}

func HashToValue(api frontend.API, hash []uints.U8, mod string) Element {
	res := StringToElement("0", mod)
	//	api.Println("RES 0 : ", res.V[0], " ", res.V[1])
	for i := len(hash) - 1; i >= 0; i-- {
		res = ProdElement(res, StringToElement("256", mod), api)
		res = AddElement(res, Element{[2]frontend.Variable{hash[i].Val, frontend.Variable(0)}, res.M}, api)
		//	api.Println("RES ", res.V[0], " ", res.V[1])
		//res = api.Mul(res, frontend.Variable(256))
		//res = api.Add(res, hash[i].Val)
	}

	return res
}

func init() {
	solver.RegisterHint(HintGetX)
}

func HintGetX(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	b := inputs[31].Cmp(big.NewInt(128))
	Y := big.NewInt(0).Mod(inputs[31], big.NewInt(128))
	for i := 30; i >= 0; i-- {
		Y.Mul(Y, big.NewInt(256))
		Y.Add(Y, inputs[i])
	}
	num := big.NewInt(0).Exp(Y, big.NewInt(2), Q)
	num = big.NewInt(0).Sub(num, big.NewInt(1))
	num = big.NewInt(0).Add(num, Q)
	num = big.NewInt(0).Mod(num, Q)

	den := big.NewInt(0).Exp(Y, big.NewInt(2), Q)
	den = big.NewInt(0).Mul(den, D)
	den = big.NewInt(0).Add(den, big.NewInt(1))
	den = big.NewInt(0).Mod(den, Q)
	den = big.NewInt(0).ModInverse(den, Q)

	left := big.NewInt(0).Mul(num, den)
	left = big.NewInt(0).Mod(left, Q)
	X := big.NewInt(0).ModSqrt(left, Q)
	X.Mod(X, Q)
	if (X.Bit(0) == 0) != (b < 0) {
		X.Sub(Q, X)
	}
	result[0] = big.NewInt(0).Mod(X, FieldBase)
	result[1] = big.NewInt(0).Div(X, FieldBase)
	Y.Mod(Y, Q)
	result[2] = big.NewInt(0).Mod(Y, FieldBase)
	result[3] = big.NewInt(0).Div(Y, FieldBase)
	if b >= 0 {
		result[4] = big.NewInt(128)
	} else {
		result[4] = big.NewInt(0)
	}
	return nil
}

func CompressToPointCircuit(cf []uints.U8, api frontend.API, uapi *uints.BinaryField[uints.U64]) (res PointCircuit) {
	var temp [32]frontend.Variable
	for i := 0; i < 32; i++ {
		temp[i] = frontend.Variable(cf[i].Val)
	}
	arr, _ := api.Compiler().NewHint(HintGetX, 5, temp[:]...)

	res.X = ElementQ{[2]frontend.Variable{arr[0], arr[1]}}
	res.Y = ElementQ{[2]frontend.Variable{arr[2], arr[3]}}
	temp[31] = api.Sub(temp[31], arr[4])
	y0, y1 := frontend.Variable(0), frontend.Variable(0)
	for i := 15; i >= 0; i-- {
		y0 = api.Mul(y0, "256")
		y1 = api.Mul(y1, "256")

		y0 = api.Add(y0, temp[i])
		y1 = api.Add(y1, temp[i+16])
	}
	OnCurveCircuit(res, api)
	return
}

//ssh -i pub_rsa lautaro@34.118.49.208
