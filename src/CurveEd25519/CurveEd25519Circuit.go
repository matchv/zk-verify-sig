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
	X, Y Element
}

func PointToCircuit(p Point) PointCircuit {
	return PointCircuit{X: BigIntToElement(p.X, Q), Y: BigIntToElement(p.Y, Q)}
}

func GetBaseCircuit() PointCircuit {
	return PointCircuit{StringToElement(BXC, QC), StringToElement(BYC, QC)}
}

// var BASEC
func AddCircuit(p1, p2 PointCircuit, api frontend.API) PointCircuit {
	X := ProdElement(
		AddElement(ProdElement(p1.X, p2.Y, api), ProdElement(p1.Y, p2.X, api), api),
		InverseElement(AddElement(BigIntToElement(big.NewInt(1), Q),
			ProdElements([]Element{StringToElement(DC, QC), p1.X, p1.Y, p2.X, p2.Y}, api), api), api), api)

	Y := ProdElement(AddElement(ProdElement(p1.Y, p2.Y, api),
		ProdElements([]Element{StringToElement("57896044618658097711785492504343953926634992332820282019728792003956564819948", QC), StringToElement(AC, QC), p1.X, p2.X}, api), api),
		InverseElement(AddElement(BigIntToElement(big.NewInt(1), Q), ProdElements([]Element{StringToElement("57896044618658097711785492504343953926634992332820282019728792003956564819948", QC), StringToElement(DC, QC), p1.X, p1.Y, p2.X, p2.Y}, api), api), api), api)

	return PointCircuit{X, Y}
}

func MulByScalarCircuit(p PointCircuit, s Element, api frontend.API) PointCircuit {
	//exp := BitsElement(AddElement(StringToElement("57896044618658097711785492504343953926634992332820282019728792003956564819948", OrdC), s, api), api)
	exp := BitsElement(s, api)
	res := PointCircuit{StringToElement("0", QC), StringToElement("1", QC)}
	for i := 0; i < 256; i++ {
		temp := AddCircuit(res, p, api)

		res.X.V[0] = api.Select(exp[i], temp.X.V[0], res.X.V[0])
		res.X.V[1] = api.Select(exp[i], temp.X.V[1], res.X.V[1])
		res.Y.V[0] = api.Select(exp[i], temp.Y.V[0], res.Y.V[0])
		res.Y.V[1] = api.Select(exp[i], temp.Y.V[1], res.Y.V[1])

		p = AddCircuit(p, p, api)
	}
	return res
}

func OnCurveCircuit(p PointCircuit, api frontend.API) {
	izq := ProdElement(StringToElement(AC, QC), ProdElement(p.X, p.X, api), api)
	izq = AddElement(izq, ProdElement(p.Y, p.Y, api), api)

	der := ProdElement(StringToElement(DC, QC), ProdElements([]Element{p.X, p.X, p.Y, p.Y}, api), api)
	der = AddElement(der, BigIntToElement(big.NewInt(1), Q), api)

	AssertEqualElement(izq, der, api)
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
