package Curve

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const QC = "57896044618658097711785492504343953926634992332820282019728792003956564819949"
const AC = "486664"
const DC = "486660"
const CofactorC = "8"
const OrdC = "7237005577332262213973186563042994240857116359379907606001950938285454250989"
const BXC = "19682211724289367445990778417013818358151178695569199618971391691394964886553"
const BYC = "46316835694926478169428394003475163141307993866256225615783033603165251855960"
const BUC = "9"
const BVC = "43114425171068552920764898935933967039370386198203806730763910166200978582548"

type PointCircuit struct {
	X, Y Element
}

func PointToCircuit(p Point) PointCircuit {
	return PointCircuit{X: BigIntToElement(p.X), Y: BigIntToElement(p.Y)}
}

func GetBaseCircuit() PointCircuit {
	return PointCircuit{StringToElement(BXC), StringToElement(BYC)}
}

// var BASEC
func AddCircuit(p1, p2 PointCircuit, api frontend.API) PointCircuit {
	X := ProdElement(
		AddElement(ProdElement(p1.X, p2.Y, api), ProdElement(p1.Y, p2.X, api), api),
		InverseElement(AddElement(BigIntToElement(big.NewInt(1)),
			ProdElements([]Element{StringToElement(DC), p1.X, p1.Y, p2.X, p2.Y}, api), api), api), api)

	Y := ProdElement(AddElement(ProdElement(p1.Y, p2.Y, api),
		ProdElements([]Element{StringToElement("57896044618658097711785492504343953926634992332820282019728792003956564819948"), StringToElement(AC), p1.X, p2.X}, api), api),
		InverseElement(AddElement(BigIntToElement(big.NewInt(1)), ProdElements([]Element{StringToElement("57896044618658097711785492504343953926634992332820282019728792003956564819948"), StringToElement(DC), p1.X, p1.Y, p2.X, p2.Y}, api), api), api), api)

	return PointCircuit{X, Y}
}

func MulByScalarCircuit(p PointCircuit, s Element, api frontend.API) PointCircuit {
	exp := BitsElement(AddElement(StringToElement("57896044618658097711785492504343953926634992332820282019728792003956564819948"), s, api), api)
	res := p
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
	izq := ProdElement(StringToElement(AC), ProdElement(p.X, p.X, api), api)
	izq = AddElement(izq, ProdElement(p.Y, p.Y, api), api)

	der := ProdElement(StringToElement(DC), ProdElements([]Element{p.X, p.X, p.Y, p.Y}, api), api)
	der = AddElement(der, BigIntToElement(big.NewInt(1)), api)

	AssertEqualElement(izq, der, api)
}

func HashToValue(uapi *uints.BinaryField[uints.U64], api frontend.API, hash []uints.U8) Element {
	res := StringToElement("0")
	//	api.Println("RES 0 : ", res.V[0], " ", res.V[1])
	for i := 0; i < len(hash); i++ {
		res = ProdElement(res, StringToElement("256"), api)
		res = AddElement(res, Element{[2]frontend.Variable{hash[i].Val, frontend.Variable(0)}}, api)
		//	api.Println("RES ", res.V[0], " ", res.V[1])
		//res = api.Mul(res, frontend.Variable(256))
		//res = api.Add(res, hash[i].Val)
	}

	return res
}
