// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import { Script, console2 } from "forge-std/Script.sol";
import { Common } from "create3-deploy/script/Common.s.sol";
import { ScriptTools } from "create3-deploy/script/ScriptTools.sol";
import "../src/EthereumMessageRootOracle.sol";

contract Deploy is Common {
    address immutable ADDR = 0x0042540F26Af0d83D34197eE1FFE831E4BDb908d;
    bytes32 immutable SALT = 0x13a2cee8eb208966d893c9b726a37f481052ea0e74a5748aaf34798058fbfeac;

    function name() public pure override returns (string memory) {
        return "Deploy";
    }

    function setUp() public override {
        super.setUp();
    }

    function run() public broadcast {
        uint64 slot = 7825376;
        uint64 proposer_index = 550054;
        bytes32 parent_root = 0x43fcc72d547536eeaf4e43454fbc82fbd3d475dbe2890f96281c5d004312ce3e;
        bytes32 state_root = 0xcea628f2339d80944daece5214c61effee317f8d9bf71ec21625e98d3c76d022;
        bytes32 body_root = 0x4e45b5935b52b809daba32f1ba9faae64af12d3f9d6847db393021c593c904c4;
        uint256 block_number = 18633272;
        bytes32 merkle_root = 0xf4036d4b1a025802e88b41881d098fd2b63a95f74d961713c2756b253a0391c6;
        bytes32 sync_committee_hash = 0x4e6ce20e67e1c347266408d0d58de1dba560025e2b60536d376d9b7af91fed24;
        bytes32 genesis_validators_root = 0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078;
        new EthereumMessageRootOracle(
            slot,
            proposer_index,
            parent_root,
            state_root,
            body_root,
            block_number,
            merkle_root,
            sync_committee_hash,
            genesis_validators_root
        );
        // bytes memory byteCode = type(EthereumMessageRootOracle).creationCode;
        // address addr = _deploy3(SALT, abi.encodePacked(byteCode, args()));
        // require(addr == ADDR, "!addr");
    }

    function args() internal pure returns (bytes memory) {
        uint64 slot = 7825376;
        uint64 proposer_index = 550054;
        bytes32 parent_root = 0x43fcc72d547536eeaf4e43454fbc82fbd3d475dbe2890f96281c5d004312ce3e;
        bytes32 state_root = 0xcea628f2339d80944daece5214c61effee317f8d9bf71ec21625e98d3c76d022;
        bytes32 body_root = 0x4e45b5935b52b809daba32f1ba9faae64af12d3f9d6847db393021c593c904c4;
        uint256 block_number = 18633272;
        bytes32 merkle_root = 0xf4036d4b1a025802e88b41881d098fd2b63a95f74d961713c2756b253a0391c6;
        bytes32 sync_committee_hash = 0x4e6ce20e67e1c347266408d0d58de1dba560025e2b60536d376d9b7af91fed24;
        bytes32 genesis_validators_root = 0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078;
        return abi.encode(
            slot,
            proposer_index,
            parent_root,
            state_root,
            body_root,
            block_number,
            merkle_root,
            sync_committee_hash,
            genesis_validators_root
        );
    }
}
