# ZK-input - runningn a verifier

This repo is a simple sample of how to create a circuit, get the proof
and its public input, and package it to properly verify them on a solidity
codebase.

## Getting the proof + public input + verifier

```sh
make all
```

## Testing solidity

Be sure that froundry/forge is installed (https://book.getfoundry.sh/getting-started/installation).

```sh
make test-solidity
```