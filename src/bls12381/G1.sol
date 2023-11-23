// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.17;

import "./Fp.sol";

/// @dev BLS12-381 G1 of affine coordinates in short Weierstrass.
/// @param x X over the base field.
/// @param y Y over the base field.
struct Bls12G1 {
    Bls12Fp x;
    Bls12Fp y;
}

/// @title BLS12G1Affine
library BLS12G1Affine {
    using BLS12FP for Bls12Fp;

    /// @dev BLS12_377_G1ADD precompile address.
    uint256 private constant G1_ADD = 0x0c;

    /// @dev Negative G1 generator
    /// @return Negative G1 generator
    function neg_generator() internal pure returns (Bls12G1 memory) {
        return Bls12G1({
            x: Bls12Fp(0x17f1d3a73197d7942695638c4fa9ac0, 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb),
            y: Bls12Fp(0x114d1d6855d545a8aa7d76c8cf2e21f2, 0x67816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca)
        });
    }

    /// @dev Returns the additive identity element of Bls12G1.
    /// @return Bls12G1(BLS12FP.zero(), BLS12FP.zero())
    function zero() internal pure returns (Bls12G1 memory) {
        return Bls12G1(BLS12FP.zero(), BLS12FP.zero());
    }

    /// @dev Returns `true` if `self` is equal to the additive identity.
    /// @param self Bls12G1.
    /// @return Result of zero check.
    function is_zero(Bls12G1 memory self) internal pure returns (bool) {
        return self.x.is_zero() && self.y.is_zero();
    }

    /// @dev Returns `true` if `self` is infinity point.
    /// @param self Bls12G1.
    /// @return Result of infinity check.
    function is_infinity(Bls12G1 memory self) internal pure returns (bool) {
        return is_zero(self);
    }

    /// @dev Returns complement in G1 for `apk-proofs`.
    /// @return Complement in G1.
    function complement() internal pure returns (Bls12G1 memory) {
        return Bls12G1({x: Bls12Fp(0, 0), y: Bls12Fp(0, 1)});
    }

    /// @dev Returns the result of `p + q`.
    /// @param p Bls12G1.
    /// @param q Bls12G1.
    /// @return z `x + y`.
    function add(Bls12G1 memory p, Bls12G1 memory q) internal view returns (Bls12G1 memory) {
        uint256[8] memory input;
        input[0] = p.x.a;
        input[1] = p.x.b;
        input[2] = p.y.a;
        input[3] = p.y.b;
        input[4] = q.x.a;
        input[5] = q.x.b;
        input[6] = q.y.a;
        input[7] = q.y.b;
        uint256[4] memory output;

        assembly ("memory-safe") {
            if iszero(staticcall(gas(), G1_ADD, input, 256, output, 128)) {
                let pt := mload(0x40)
                returndatacopy(pt, 0, returndatasize())
                revert(pt, returndatasize())
            }
        }

        return from(output);
    }

    /// @dev Derive Bls12G1 from uint256[4].
    /// @param x uint256[4].
    /// @return Bls12G1.
    function from(uint256[4] memory x) internal pure returns (Bls12G1 memory) {
        return Bls12G1(Bls12Fp(x[0], x[1]), Bls12Fp(x[2], x[3]));
    }
}
