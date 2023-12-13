package signature_verifier

import (
	"ed25519/curve_ed25519"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// / Signature : R.X, R.Y, S
const InputLarge = (32 + 32 + 32 + MLAR + 30) / 31

type Signature struct {
	Rc  [32]uints.U8   `gnark:",public"`
	Sc  [32]uints.U8   `gnark:",public"`
	Ac  [32]uints.U8   `gnark:",public"`
	Msg [MLAR]uints.U8 `gnark:",public"`
	//	Input [InputLarge]frontend.Variable `gnark:",public"`
}

func (sig *Signature) GetAllCircuit(uapi *uints.BinaryField[uints.U64], api frontend.API) (Rc, Sc, Ac [32]uints.U8, Msg [MLAR]uints.U8) {
	Rc = sig.Rc
	Sc = sig.Sc
	Ac = sig.Ac
	Msg = sig.Msg
	return
}

func (sig *Signature) SetAll(R curve_ed25519.Point, S *big.Int, A curve_ed25519.Point, Msg [MLAR]byte) {
	sig.Rc = [32]uints.U8(R.CompressFormCircuit())
	sig.Sc = [32]uints.U8(BigIntToUint8(S))
	sig.Ac = [32]uints.U8(A.CompressFormCircuit())
	for i := 0; i < MLAR; i++ {
		sig.Msg[i] = uints.NewU8(Msg[i])
	}
}
