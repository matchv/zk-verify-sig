build-solidity:
	go run main.go

build-abi: verifier.sol
	forge build -C ./solidity/test/src/Verifier.sol -o abi
	jq '.abi' ./abi/verifier.sol/Verifier.json > ./abi/Verifier.json
	rm -rf ./abi/verifier.sol

all:
	make build-solidity
	make build-abi

test-solidity:
	forge test --root solidity/test