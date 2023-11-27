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

import "forge-std/Test.sol";
import "../src/bls12381/BLS.sol";

contract BLSTest is Test {
    function test_to_compressed_g1() public {
        bytes memory uncompressed =
            hex"0e639218d454cef60b342047e7b3577d26743c032cc02e615aafd51ee47e0a08b7932a1cc5fe34ad8e70050503dbe0bf12c456f91daf3bfe59b63c107738f803ad425409452d154cc48930f36af446bf43c91a3f7fd42017876a61bc12b20196";
        bytes memory compressed = BLS.to_compressed_g1(uncompressed);
        assertEq(
            compressed,
            hex"ae639218d454cef60b342047e7b3577d26743c032cc02e615aafd51ee47e0a08b7932a1cc5fe34ad8e70050503dbe0bf"
        );
    }
}
