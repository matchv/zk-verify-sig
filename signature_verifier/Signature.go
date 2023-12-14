package signature_verifier

import (
	"ed25519/curve_ed25519"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// / Signature : R.X, R.Y, S
const InputLarge = (32 + 32 + 32 + MLAR + 30) / 31

type Signature struct {
	Rc    [32]uints.U8                  `gnark:",public"`
	Sc    [32]uints.U8                  `gnark:",public"`
	Ac    [32]uints.U8                  `gnark:",public"`
	Msg   [MLAR]uints.U8                `gnark:",public"`
	Input [InputLarge]frontend.Variable `gnark:",public"`
}

func init() {
	solver.RegisterHint(frontendVariableToU8Hint)
}

func frontendVariableToU8Hint(_ *big.Int, inputs []*big.Int, result []*big.Int) error {
	s := inputs[0].FillBytes(make([]byte, 32))
	for i := 0; i < 32; i++ {
		result[i] = big.NewInt(0).SetUint64(uint64(s[i]))
	}
	return nil
}

func frontendVariableToU8(v frontend.Variable, uapi *uints.BinaryField[uints.U64], api frontend.API) (ret [32]uints.U8) {
	variable, _ := api.Compiler().NewHint(frontendVariableToU8Hint, 32, v)
	v2 := frontend.Variable(0)
	for i := 0; i < 32; i++ {
		v2 = api.Add(variable[i], api.Mul(v2, frontend.Variable(256)))
		ret[i] = uapi.ByteValueOf(variable[i])
	}
	api.AssertIsEqual(v, v2)
	return
}

func (sig *Signature) GetAllCircuit(uapi *uints.BinaryField[uints.U64], api frontend.API) (Rc, Sc, Ac [32]uints.U8, Msg [MLAR]uints.U8) {
	output := make([]uints.U8, 0, InputLarge*31)
	uapi2, _ := uints.New[uints.U64](api)
	for i := 0; i < InputLarge; i++ {
		loc := frontendVariableToU8(sig.Input[i], uapi2, api)
		output = append(output, loc[1:32]...)
	}
	Rc = [32]uints.U8{}
	Sc = [32]uints.U8{}
	Ac = [32]uints.U8{}
	Msg = [MLAR]uints.U8{}
	fmt.Println(len(output))
	copy(Rc[:], output[0:32])
	copy(Sc[:], output[32:64])
	copy(Ac[:], output[64:96])
	copy(Msg[:], output[96:96+MLAR])
	/*Rc = [32]uints.U8(output[0:32])
	Sc = [32]uints.U8(output[32:64])
	Ac = [32]uints.U8(output[64:96])
	Msg = [MLAR]uints.U8(output[96 : 96+MLAR])*/

	fmt.Println("Check Rc")
	fmt.Println(sig.Rc)
	fmt.Println(Rc)
	for i := 0; i < 32; i++ {
		uapi.ByteAssertEq(sig.Rc[i], output[i])
		uapi.ByteAssertEq(sig.Rc[i], Rc[i])
	}
	fmt.Println("Check Sc")
	fmt.Println(sig.Sc)
	fmt.Println(Sc)
	for i := 0; i < 32; i++ {
		uapi.ByteAssertEq(sig.Sc[i], output[i+32])
		uapi.ByteAssertEq(sig.Sc[i], Sc[i])
	}
	fmt.Println("Check Ac")
	fmt.Println(sig.Ac)
	fmt.Println(Ac)
	for i := 0; i < 32; i++ {
		uapi.ByteAssertEq(sig.Ac[i], output[i+64])
		uapi.ByteAssertEq(sig.Ac[i], Ac[i])
	}
	fmt.Println("Check Msg")
	fmt.Println(sig.Msg)
	fmt.Println(Msg)
	for i := 0; i < MLAR; i++ {
		uapi.ByteAssertEq(sig.Msg[i], output[i+96])
		uapi.ByteAssertEq(sig.Msg[i], Msg[i])
	}
	/*Rc = sig.Rc
	Sc = sig.Sc
	Ac = sig.Ac
	Msg = sig.Msg*/
	return
}

func (sig *Signature) SetAll(R curve_ed25519.Point, S *big.Int, A curve_ed25519.Point, Msg [MLAR]byte) {
	input := make([]byte, 0, InputLarge*31)
	input = append(input, R.CompressForm()...)
	input = append(input, InvertArray(S.FillBytes(make([]byte, 32)))...)
	input = append(input, A.CompressForm()...)
	input = append(input, Msg[:]...)
	for len(input) < InputLarge*31 {
		input = append(input, 0)
	}
	for i := 0; i < InputLarge; i++ {
		temp := make([]byte, 1, 32)
		temp[0] = 0
		temp = append(temp, input[i*31:(i+1)*31]...)
		sig.Input[i] = frontend.Variable(new(big.Int).SetBytes(temp))
	}
	sig.Rc = [32]uints.U8(R.CompressFormCircuit())
	sig.Sc = [32]uints.U8(BigIntToUint8(S))
	sig.Ac = [32]uints.U8(A.CompressFormCircuit())
	for i := 0; i < MLAR; i++ {
		sig.Msg[i] = uints.NewU8(Msg[i])
	}
}
