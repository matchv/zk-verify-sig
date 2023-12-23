/*
const MLAR = 115
const InputLarge = 7
func SetAll(Sig [64]byte, A [32]byte, Msg [MLAR]byte) (output [7]big.Int) {
	input := make([]byte, 0, InputLarge*31)
	input = append(input, Sig...)
	input = append(input, A...)
	input = append(input, Msg[:]...)
	for len(input) < InputLarge*31 {
		input = append(input, 0)
	}
	for i := 0; i < InputLarge; i++ {
		temp := make([]byte, 1, 32)
		temp[0] = 0
		temp = append(temp, input[i*31:(i+1)*31]...)
        output[i] = new(big.Int).SetBytes(temp)
    }
}
*/
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SignatureVerifier {
    uint256 constant MLAR = 115;
    uint256 constant InputLarge = 7;

    function SetAll(bytes memory pubKey, bytes memory Msg, bytes memory Sig) public pure returns (uint256[] memory output) {
        bytes memory input = new bytes(InputLarge * 31);

        for (uint256 i = 0; i < Sig.length; i++) {
            input[i] = Sig[i];
        }

        for (uint256 i = 0; i < pubKey.length; i++) {
            input[Sig.length + i] = pubKey[i];
        }

        for (uint256 i = 0; i < Msg.length; i++) {
            input[Sig.length + pubKey.length + i] = Msg[i];
        }

        for (uint256 i = 0; i < InputLarge; i++) {
            output[i] = 0;
            
            for (uint256 j = 0; j < 31; j++) {
                output[i] = output[i] * 256 + uint256(uint8(input[i * 31 + j]));
            }
        }
    }
}
