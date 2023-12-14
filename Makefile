.PHONY: all fmt clean test salt
.PHONY: tools foundry sync create3

-include .env

all    :; @forge build --force
fmt    :; @forge fmt
clean  :; @forge clean
test   :; @forge test
# deploy :; @forge script script/Deploy.s.sol:Deploy --chain ${chain-id} --broadcast --verify
# deploy :; @forge script script/Deploy.s.sol:Deploy --rpc-url http://192.168.132.159:9944 --broadcast
deploy :; @forge script script/Deploy.s.sol:Deploy --rpc-url https://pangolin-rpc.darwinia.network --broadcast
e2e-test:; @forge script script/Deploy.s.sol:Deploy --sig "test_import_finalized_header()" --rpc-url https://pangolin-rpc.darwinia.network --broadcast

salt   :; @create3 -s 000000000000
sync   :; @git submodule update --recursive
create3:; @cargo install --git https://github.com/darwinia-network/create3-deploy -f

tools  :  foundry create3
foundry:; curl -L https://foundry.paradigm.xyz | bash
