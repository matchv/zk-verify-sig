package main

import (
	"encoding/hex"
	"log"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"

	crand "crypto/rand"
)

func TestAsd(t *testing.T) {
	var Sig [64]byte
	var pubKey [32]byte
	var msg [115]byte
	crand.Read(Sig[:])
	crand.Read(pubKey[:])
	crand.Read(msg[:])

	r, _ := os.Open("abi/Verifier.json")

	abiContract, err := abi.JSON(r)
	packedInput, err := abiContract.Pack("SetAll", Sig, pubKey, msg)
	if err != nil {
		log.Println("ASD")
		log.Fatal(err)
	}
	log.Println(hex.EncodeToString(packedInput))
	log.Println(len(hex.EncodeToString(packedInput)))
	log.Println(len(hex.EncodeToString(packedInput)) / 64)
}
