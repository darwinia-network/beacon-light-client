// This file is part of Darwinia.
// Copyright (C) 2018-2022 Darwinia Network
// SPDX-License-Identifier: GPL-3.0
//
// Darwinia is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Darwinia is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Darwinia. If not, see <https://www.gnu.org/licenses/>.

pragma solidity 0.8.17;

import "./interfaces/ILightClient.sol";
import "./StorageProof.sol";

contract EthereumMessageRootOracle {
    address immutable LIGHT_CLIENT;
    address constant ORMP = 0x00000000001523057a05d6293C1e5171eE33eE0A;
    bytes32 constant SLOT = 0x0000000000000000000000000000000000000000000000000000000000000006;

    bytes32 messageRoot = 0x27ae5ba08d7291c96c8cbddcc148bf48a6d68c7974b94356f53754ef6171d757;

    struct Proof {
        bytes[] accountProof;
        bytes[] storageProof;
    }

    event FinalizedMessageRootImported(uint256 indexed blockNumber, bytes32 indexed messageRoot);

    constructor(address lightClient) {
        LIGHT_CLIENT = lightClient;
    }

    function blockNumber() public view returns (uint256) {
        return ILightClient(LIGHT_CLIENT).block_number();
    }

    function stateRoot() public view returns (bytes32) {
        return ILightClient(LIGHT_CLIENT).merkle_root();
    }

    function importMessageRoot(bytes calldata encodedProof) public {
        Proof memory proof = abi.decode(encodedProof, (Proof));
        bytes32 value = toBytes32(StorageProof.verify(stateRoot(), ORMP, proof.accountProof, SLOT, proof.storageProof));
        require(value != messageRoot, "same");
        messageRoot = value;
        emit FinalizedMessageRootImported(blockNumber(), value);
    }

    function toBytes32(bytes memory source) internal pure returns (bytes32 result) {
        require(source.length == 32, "!len");
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(add(source, 32))
        }
    }
}
