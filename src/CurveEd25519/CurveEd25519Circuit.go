package Curve

import (
	"math/big"

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
	izq := ProdElementQ(StringToElementQ(AC), ProdElementQ(p.X, p.X, api), api)
	izq = AddElementQ(izq, ProdElementQ(p.Y, p.Y, api), api)

	der := ProdElementQ(StringToElementQ(DC), ProdElementsQ([]ElementQ{p.X, p.X, p.Y, p.Y}, api), api)
	der = AddElementQ(der, BigIntToElementQ(big.NewInt(1)), api)

	AssertEqualElementQ(izq, der, api)
}

func HashToValueQ(uapi *uints.BinaryField[uints.U64], api frontend.API, hash []uints.U8) ElementQ {
	res := StringToElementQ("0")
	//	api.Println("RES 0 : ", res.V[0], " ", res.V[1])
	for i := 0; i < len(hash); i++ {
		res = ProdElementQ(res, StringToElementQ("256"), api)
		res = AddElementQ(res, ElementQ{[2]frontend.Variable{hash[i].Val, frontend.Variable(0)}}, api)
		//	api.Println("RES ", res.V[0], " ", res.V[1])
		//res = api.Mul(res, frontend.Variable(256))
		//res = api.Add(res, hash[i].Val)
	}

	return res
}

func HashToValueO(uapi *uints.BinaryField[uints.U64], api frontend.API, hash []uints.U8) ElementO {
	res := StringToElementO("0")
	//	api.Println("RES 0 : ", res.V[0], " ", res.V[1])
	for i := 0; i < len(hash); i++ {
		res = ProdElementO(res, StringToElementO("256"), api)
		res = AddElementO(res, ElementO{[2]frontend.Variable{hash[i].Val, frontend.Variable(0)}}, api)
		//	api.Println("RES ", res.V[0], " ", res.V[1])
		//res = api.Mul(res, frontend.Variable(256))
		//res = api.Add(res, hash[i].Val)
	}

	return res
}

func HashToValue(uapi *uints.BinaryField[uints.U64], api frontend.API, hash []uints.U8, mod string) Element {
	res := StringToElement("0", mod)
	//	api.Println("RES 0 : ", res.V[0], " ", res.V[1])
	for i := 0; i < len(hash); i++ {
		res = ProdElement(res, StringToElement("256", mod), api)
		res = AddElement(res, Element{[2]frontend.Variable{hash[i].Val, frontend.Variable(0)}, res.M}, api)
		//	api.Println("RES ", res.V[0], " ", res.V[1])
		//res = api.Mul(res, frontend.Variable(256))
		//res = api.Add(res, hash[i].Val)
	}

	return res
}
