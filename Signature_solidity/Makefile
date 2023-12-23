test: Signature.sol
	forge build -C Signature.sol -o abi
	jq '.abi' Signature.json > Signature.json
	rm -rf ./abi/verifier.sol
	go run main.go
