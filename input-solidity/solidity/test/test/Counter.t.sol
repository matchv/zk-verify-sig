// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";

// import {Counter} from "../src/Counter.sol";
import {Verifier} from "../src/Verifier.sol";

contract CounterTest is Test {
    Verifier public verifier;

    function setUp() public {
        verifier = new Verifier();
    }

    function test_CorrectProof() public view {
        // the first uint256 is rubbish, coming from the abi.encode(...) call. TODO: understand why

        // [firstuint256-rubbish, proof: uint256[8], publicInput: uint256[1]]
        // bytes
        //     memory proof = hex"1b81f82924c31f13c0a9e4ca3e7babcdb9051f9343b38a9322ccc18e20e33dedf06bc40d1094515a29701d6cd0c0aea9ade140abd547241bebcc607beed56e3725c5bf6b09c3414dcc9cf606968a5b092b8248504f1416c2db80f3986f7fbe2f43b1e03122318255264cb6a4ab296332fb5312998fa7da3c0b5236c333443745442566a8103112de0dae2eb7e4e4744017dbbf1727624abb27ec74c4bc50bd9c12a75d7d1d177d963010f3164b1154d6314a37bf17a7845b7e99f24f4b483ecc6bbe09d002b0c3fb039828db9abce03d613de01ca0d6d5d74c5b2a480e0e8a8e65e980e92f9182c4b36759e9783f020f5ec30f4f297939c963aec0d898b242ec7e4b13b60000000000000000000000000000000000000000000000000000000000000023";
        bytes
            memory proof = hex"24c31f13c0a9e4ca3e7babcdb9051f9343b38a9322ccc18e20e33dedf06bc40d1094515a29701d6cd0c0aea9ade140abd547241bebcc607beed56e3725c5bf6b09c3414dcc9cf606968a5b092b8248504f1416c2db80f3986f7fbe2f43b1e03122318255264cb6a4ab296332fb5312998fa7da3c0b5236c333443745442566a8103112de0dae2eb7e4e4744017dbbf1727624abb27ec74c4bc50bd9c12a75d7d1d177d963010f3164b1154d6314a37bf17a7845b7e99f24f4b483ecc6bbe09d002b0c3fb039828db9abce03d613de01ca0d6d5d74c5b2a480e0e8a8e65e980e92f9182c4b36759e9783f020f5ec30f4f297939c963aec0d898b242ec7e4b13b6";
        bytes
            memory publicInput = hex"0000000000000000000000000000000000000000000000000000000000000023";

        uint256[8] memory proofFinal = abi.decode(proof, (uint256[8]));
        uint256[1] memory publicInputFinal = abi.decode(
            publicInput,
            (uint256[1])
        );
        verifier.verifyProof(proofFinal, publicInputFinal);
    }
}
