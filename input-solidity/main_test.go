package main

import (
	"encoding/hex"
	"log"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

func TestAsd(t *testing.T) {
	var _ CubicCircuit

	r, _ := os.Open("abi/Verifier.json")

	abiContract, err := abi.JSON(r)
	if err != nil {
		t.Fatal(err)
	}

	// contractABI.Pack("verifyProof", 1)

	proofHexString := "24c31f13c0a9e4ca3e7babcdb9051f9343b38a9322ccc18e20e33dedf06bc40d1094515a29701d6cd0c0aea9ade140abd547241bebcc607beed56e3725c5bf6b09c3414dcc9cf606968a5b092b8248504f1416c2db80f3986f7fbe2f43b1e03122318255264cb6a4ab296332fb5312998fa7da3c0b5236c333443745442566a8103112de0dae2eb7e4e4744017dbbf1727624abb27ec74c4bc50bd9c12a75d7d1d177d963010f3164b1154d6314a37bf17a7845b7e99f24f4b483ecc6bbe09d002b0c3fb039828db9abce03d613de01ca0d6d5d74c5b2a480e0e8a8e65e980e92f9182c4b36759e9783f020f5ec30f4f297939c963aec0d898b242ec7e4b13b60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	proofBytes, _ := hex.DecodeString(proofHexString)

	// solidity contract inputs
	var (
		a          [2]*big.Int
		b          [2][2]*big.Int
		c          [2]*big.Int
		proofInput [8]*big.Int
		input      [1]*big.Int
	)

	// get proof bytes
	const fpSize = 4 * 8
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	proofInput[0] = a[0]
	proofInput[1] = a[1]
	proofInput[2] = b[0][0]
	proofInput[3] = b[0][1]
	proofInput[4] = b[1][0]
	proofInput[5] = b[1][1]
	proofInput[6] = c[0]
	proofInput[7] = c[1]

	// public witness
	input[0] = new(big.Int).SetUint64(uint64(35))

	packedInput, err := abiContract.Pack("verifyProof", proofInput, input)
	if err != nil {
		log.Println("ASD")
		log.Fatal(err)
	}
	log.Println(hex.EncodeToString(packedInput))
	log.Println(len(hex.EncodeToString(packedInput)))
	log.Println(len(hex.EncodeToString(packedInput)) / 64)
}
