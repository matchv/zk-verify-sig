package Curve

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
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
	X, Y frontend.Variable
}

var BASEC = PointCircuit{BXC, BYC}

func Inverse(b frontend.Variable, api frontend.API) frontend.Variable {
	b0 := b
	res := frontend.Variable(1)
	for q, _ := big.NewInt(0).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819947", 10); q.Cmp(big.NewInt(0)) > 0; q.Div(q, big.NewInt(2)) {
		if big.NewInt(0).Mod(q, big.NewInt(2)).Cmp(big.NewInt(0)) == 1 {
			res = ModCircuit(api.Mul(res, b), api)
		}
		b = ModCircuit(api.Mul(b, b), api)
	}
	Prod := api.Mul(b0, res)
	Prod = ModCircuit(Prod, api)
	api.AssertIsEqual(Prod, frontend.Variable(1))
	return res
}

func AddCircuit(p1, p2 PointCircuit, api frontend.API) PointCircuit {
	X := api.Mul(
		api.Add(api.Mul(p1.X, p2.Y), api.Mul(p1.Y, p2.X)),
		Inverse(api.Add(frontend.Variable(1), api.Mul(DC, p1.X, p2.X, p1.Y, p2.Y)), api))
	Y := api.Mul(
		api.Add(api.Mul(p1.Y, p2.Y), api.Mul(frontend.Variable(-1), AC, p1.X, p2.X)),
		Inverse(api.Add(frontend.Variable(1), api.Mul(frontend.Variable(-1), DC, p1.X, p1.Y, p2.X, p2.Y)), api))

	X = ModCircuit(X, api)
	Y = ModCircuit(Y, api)
	return PointCircuit{X, Y}
}
