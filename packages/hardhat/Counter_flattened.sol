// Sources flattened with hardhat v2.26.3 https://hardhat.org

// SPDX-License-Identifier: BSD-3-Clause-Clear AND MIT AND UNLICENSED

// File @fhenixprotocol/cofhe-contracts/ICofhe.sol@v0.0.13

// Original license: SPDX_License_Identifier: UNLICENSED
pragma solidity >=0.8.25 <0.9.0;

struct EncryptedInput {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEbool {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint8 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint16 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint32 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint64 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint128 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint256 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}
struct InEaddress {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}


// Order is set as in fheos/precompiles/types/types.go
enum FunctionId {
    _0,             // 0 - GetNetworkKey
    _1,             // 1 - Verify
    cast,           // 2
    sealoutput,     // 3
    select,         // 4 - select
    _5,             // 5 - req
    decrypt,        // 6
    sub,            // 7
    add,            // 8
    xor,            // 9
    and,            // 10
    or,             // 11
    not,            // 12
    div,            // 13
    rem,            // 14
    mul,            // 15
    shl,            // 16
    shr,            // 17
    gte,            // 18
    lte,            // 19
    lt,             // 20
    gt,             // 21
    min,            // 22
    max,            // 23
    eq,             // 24
    ne,             // 25
    trivialEncrypt, // 26
    random,         // 27
    rol,            // 28
    ror,            // 29
    square,         // 30
    _31             // 31
}

interface ITaskManager {
    function createTask(uint8 returnType, FunctionId funcId, uint256[] memory encryptedInputs, uint256[] memory extraInputs) external returns (uint256);

    function createDecryptTask(uint256 ctHash, address requestor) external;
    function verifyInput(EncryptedInput memory input, address sender) external returns (uint256);

    function allow(uint256 ctHash, address account) external;
    function isAllowed(uint256 ctHash, address account) external returns (bool);
    function allowGlobal(uint256 ctHash) external;
    function allowTransient(uint256 ctHash, address account) external;
    function getDecryptResultSafe(uint256 ctHash) external view returns (uint256, bool);
    function getDecryptResult(uint256 ctHash) external view returns (uint256);
}

library Utils {
    // Values used to communicate types to the runtime.
    // Must match values defined in warp-drive protobufs for everything to
    uint8 internal constant EUINT8_TFHE = 2;
    uint8 internal constant EUINT16_TFHE = 3;
    uint8 internal constant EUINT32_TFHE = 4;
    uint8 internal constant EUINT64_TFHE = 5;
    uint8 internal constant EUINT128_TFHE = 6;
    uint8 internal constant EUINT256_TFHE = 8;
    uint8 internal constant EADDRESS_TFHE = 7;
    uint8 internal constant EBOOL_TFHE = 0;

    function functionIdToString(FunctionId _functionId) internal pure returns (string memory) {
        if (_functionId == FunctionId.cast) return "cast";
        if (_functionId == FunctionId.sealoutput) return "sealOutput";
        if (_functionId == FunctionId.select) return "select";
        if (_functionId == FunctionId.decrypt) return "decrypt";
        if (_functionId == FunctionId.sub) return "sub";
        if (_functionId == FunctionId.add) return "add";
        if (_functionId == FunctionId.xor) return "xor";
        if (_functionId == FunctionId.and) return "and";
        if (_functionId == FunctionId.or) return "or";
        if (_functionId == FunctionId.not) return "not";
        if (_functionId == FunctionId.div) return "div";
        if (_functionId == FunctionId.rem) return "rem";
        if (_functionId == FunctionId.mul) return "mul";
        if (_functionId == FunctionId.shl) return "shl";
        if (_functionId == FunctionId.shr) return "shr";
        if (_functionId == FunctionId.gte) return "gte";
        if (_functionId == FunctionId.lte) return "lte";
        if (_functionId == FunctionId.lt) return "lt";
        if (_functionId == FunctionId.gt) return "gt";
        if (_functionId == FunctionId.min) return "min";
        if (_functionId == FunctionId.max) return "max";
        if (_functionId == FunctionId.eq) return "eq";
        if (_functionId == FunctionId.ne) return "ne";
        if (_functionId == FunctionId.trivialEncrypt) return "trivialEncrypt";
        if (_functionId == FunctionId.random) return "random";
        if (_functionId == FunctionId.rol) return "rol";
        if (_functionId == FunctionId.ror) return "ror";
        if (_functionId == FunctionId.square) return "square";

        return "";
    }

    function inputFromEbool(InEbool memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EBOOL_TFHE,
            signature: input.signature
        });
    }

    function inputFromEuint8(InEuint8 memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EUINT8_TFHE,
            signature: input.signature
        });
    }

    function inputFromEuint16(InEuint16 memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EUINT16_TFHE,
            signature: input.signature
        });
    }

    function inputFromEuint32(InEuint32 memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EUINT32_TFHE,
            signature: input.signature
        });
    }

    function inputFromEuint64(InEuint64 memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EUINT64_TFHE,
            signature: input.signature
        });
    }

    function inputFromEuint128(InEuint128 memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EUINT128_TFHE,
            signature: input.signature
        });
    }

    function inputFromEuint256(InEuint256 memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EUINT256_TFHE,
            signature: input.signature
        });
    }

    function inputFromEaddress(InEaddress memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EADDRESS_TFHE,
            signature: input.signature
        });
    }
}


// File @openzeppelin/contracts/utils/math/SafeCast.sol@v5.4.0

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/math/SafeCast.sol)
// This file was procedurally generated from scripts/generate/templates/SafeCast.js.

pragma solidity ^0.8.20;

/**
 * @dev Wrappers over Solidity's uintXX/intXX/bool casting operators with added overflow
 * checks.
 *
 * Downcasting from uint256/int256 in Solidity does not revert on overflow. This can
 * easily result in undesired exploitation or bugs, since developers usually
 * assume that overflows raise errors. `SafeCast` restores this intuition by
 * reverting the transaction when such an operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeCast {
    /**
     * @dev Value doesn't fit in an uint of `bits` size.
     */
    error SafeCastOverflowedUintDowncast(uint8 bits, uint256 value);

    /**
     * @dev An int value doesn't fit in an uint of `bits` size.
     */
    error SafeCastOverflowedIntToUint(int256 value);

    /**
     * @dev Value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedIntDowncast(uint8 bits, int256 value);

    /**
     * @dev An uint value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedUintToInt(uint256 value);

    /**
     * @dev Returns the downcasted uint248 from uint256, reverting on
     * overflow (when the input is greater than largest uint248).
     *
     * Counterpart to Solidity's `uint248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toUint248(uint256 value) internal pure returns (uint248) {
        if (value > type(uint248).max) {
            revert SafeCastOverflowedUintDowncast(248, value);
        }
        return uint248(value);
    }

    /**
     * @dev Returns the downcasted uint240 from uint256, reverting on
     * overflow (when the input is greater than largest uint240).
     *
     * Counterpart to Solidity's `uint240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toUint240(uint256 value) internal pure returns (uint240) {
        if (value > type(uint240).max) {
            revert SafeCastOverflowedUintDowncast(240, value);
        }
        return uint240(value);
    }

    /**
     * @dev Returns the downcasted uint232 from uint256, reverting on
     * overflow (when the input is greater than largest uint232).
     *
     * Counterpart to Solidity's `uint232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toUint232(uint256 value) internal pure returns (uint232) {
        if (value > type(uint232).max) {
            revert SafeCastOverflowedUintDowncast(232, value);
        }
        return uint232(value);
    }

    /**
     * @dev Returns the downcasted uint224 from uint256, reverting on
     * overflow (when the input is greater than largest uint224).
     *
     * Counterpart to Solidity's `uint224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toUint224(uint256 value) internal pure returns (uint224) {
        if (value > type(uint224).max) {
            revert SafeCastOverflowedUintDowncast(224, value);
        }
        return uint224(value);
    }

    /**
     * @dev Returns the downcasted uint216 from uint256, reverting on
     * overflow (when the input is greater than largest uint216).
     *
     * Counterpart to Solidity's `uint216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toUint216(uint256 value) internal pure returns (uint216) {
        if (value > type(uint216).max) {
            revert SafeCastOverflowedUintDowncast(216, value);
        }
        return uint216(value);
    }

    /**
     * @dev Returns the downcasted uint208 from uint256, reverting on
     * overflow (when the input is greater than largest uint208).
     *
     * Counterpart to Solidity's `uint208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toUint208(uint256 value) internal pure returns (uint208) {
        if (value > type(uint208).max) {
            revert SafeCastOverflowedUintDowncast(208, value);
        }
        return uint208(value);
    }

    /**
     * @dev Returns the downcasted uint200 from uint256, reverting on
     * overflow (when the input is greater than largest uint200).
     *
     * Counterpart to Solidity's `uint200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toUint200(uint256 value) internal pure returns (uint200) {
        if (value > type(uint200).max) {
            revert SafeCastOverflowedUintDowncast(200, value);
        }
        return uint200(value);
    }

    /**
     * @dev Returns the downcasted uint192 from uint256, reverting on
     * overflow (when the input is greater than largest uint192).
     *
     * Counterpart to Solidity's `uint192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toUint192(uint256 value) internal pure returns (uint192) {
        if (value > type(uint192).max) {
            revert SafeCastOverflowedUintDowncast(192, value);
        }
        return uint192(value);
    }

    /**
     * @dev Returns the downcasted uint184 from uint256, reverting on
     * overflow (when the input is greater than largest uint184).
     *
     * Counterpart to Solidity's `uint184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toUint184(uint256 value) internal pure returns (uint184) {
        if (value > type(uint184).max) {
            revert SafeCastOverflowedUintDowncast(184, value);
        }
        return uint184(value);
    }

    /**
     * @dev Returns the downcasted uint176 from uint256, reverting on
     * overflow (when the input is greater than largest uint176).
     *
     * Counterpart to Solidity's `uint176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toUint176(uint256 value) internal pure returns (uint176) {
        if (value > type(uint176).max) {
            revert SafeCastOverflowedUintDowncast(176, value);
        }
        return uint176(value);
    }

    /**
     * @dev Returns the downcasted uint168 from uint256, reverting on
     * overflow (when the input is greater than largest uint168).
     *
     * Counterpart to Solidity's `uint168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toUint168(uint256 value) internal pure returns (uint168) {
        if (value > type(uint168).max) {
            revert SafeCastOverflowedUintDowncast(168, value);
        }
        return uint168(value);
    }

    /**
     * @dev Returns the downcasted uint160 from uint256, reverting on
     * overflow (when the input is greater than largest uint160).
     *
     * Counterpart to Solidity's `uint160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toUint160(uint256 value) internal pure returns (uint160) {
        if (value > type(uint160).max) {
            revert SafeCastOverflowedUintDowncast(160, value);
        }
        return uint160(value);
    }

    /**
     * @dev Returns the downcasted uint152 from uint256, reverting on
     * overflow (when the input is greater than largest uint152).
     *
     * Counterpart to Solidity's `uint152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toUint152(uint256 value) internal pure returns (uint152) {
        if (value > type(uint152).max) {
            revert SafeCastOverflowedUintDowncast(152, value);
        }
        return uint152(value);
    }

    /**
     * @dev Returns the downcasted uint144 from uint256, reverting on
     * overflow (when the input is greater than largest uint144).
     *
     * Counterpart to Solidity's `uint144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toUint144(uint256 value) internal pure returns (uint144) {
        if (value > type(uint144).max) {
            revert SafeCastOverflowedUintDowncast(144, value);
        }
        return uint144(value);
    }

    /**
     * @dev Returns the downcasted uint136 from uint256, reverting on
     * overflow (when the input is greater than largest uint136).
     *
     * Counterpart to Solidity's `uint136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toUint136(uint256 value) internal pure returns (uint136) {
        if (value > type(uint136).max) {
            revert SafeCastOverflowedUintDowncast(136, value);
        }
        return uint136(value);
    }

    /**
     * @dev Returns the downcasted uint128 from uint256, reverting on
     * overflow (when the input is greater than largest uint128).
     *
     * Counterpart to Solidity's `uint128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toUint128(uint256 value) internal pure returns (uint128) {
        if (value > type(uint128).max) {
            revert SafeCastOverflowedUintDowncast(128, value);
        }
        return uint128(value);
    }

    /**
     * @dev Returns the downcasted uint120 from uint256, reverting on
     * overflow (when the input is greater than largest uint120).
     *
     * Counterpart to Solidity's `uint120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toUint120(uint256 value) internal pure returns (uint120) {
        if (value > type(uint120).max) {
            revert SafeCastOverflowedUintDowncast(120, value);
        }
        return uint120(value);
    }

    /**
     * @dev Returns the downcasted uint112 from uint256, reverting on
     * overflow (when the input is greater than largest uint112).
     *
     * Counterpart to Solidity's `uint112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toUint112(uint256 value) internal pure returns (uint112) {
        if (value > type(uint112).max) {
            revert SafeCastOverflowedUintDowncast(112, value);
        }
        return uint112(value);
    }

    /**
     * @dev Returns the downcasted uint104 from uint256, reverting on
     * overflow (when the input is greater than largest uint104).
     *
     * Counterpart to Solidity's `uint104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toUint104(uint256 value) internal pure returns (uint104) {
        if (value > type(uint104).max) {
            revert SafeCastOverflowedUintDowncast(104, value);
        }
        return uint104(value);
    }

    /**
     * @dev Returns the downcasted uint96 from uint256, reverting on
     * overflow (when the input is greater than largest uint96).
     *
     * Counterpart to Solidity's `uint96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toUint96(uint256 value) internal pure returns (uint96) {
        if (value > type(uint96).max) {
            revert SafeCastOverflowedUintDowncast(96, value);
        }
        return uint96(value);
    }

    /**
     * @dev Returns the downcasted uint88 from uint256, reverting on
     * overflow (when the input is greater than largest uint88).
     *
     * Counterpart to Solidity's `uint88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toUint88(uint256 value) internal pure returns (uint88) {
        if (value > type(uint88).max) {
            revert SafeCastOverflowedUintDowncast(88, value);
        }
        return uint88(value);
    }

    /**
     * @dev Returns the downcasted uint80 from uint256, reverting on
     * overflow (when the input is greater than largest uint80).
     *
     * Counterpart to Solidity's `uint80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toUint80(uint256 value) internal pure returns (uint80) {
        if (value > type(uint80).max) {
            revert SafeCastOverflowedUintDowncast(80, value);
        }
        return uint80(value);
    }

    /**
     * @dev Returns the downcasted uint72 from uint256, reverting on
     * overflow (when the input is greater than largest uint72).
     *
     * Counterpart to Solidity's `uint72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toUint72(uint256 value) internal pure returns (uint72) {
        if (value > type(uint72).max) {
            revert SafeCastOverflowedUintDowncast(72, value);
        }
        return uint72(value);
    }

    /**
     * @dev Returns the downcasted uint64 from uint256, reverting on
     * overflow (when the input is greater than largest uint64).
     *
     * Counterpart to Solidity's `uint64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toUint64(uint256 value) internal pure returns (uint64) {
        if (value > type(uint64).max) {
            revert SafeCastOverflowedUintDowncast(64, value);
        }
        return uint64(value);
    }

    /**
     * @dev Returns the downcasted uint56 from uint256, reverting on
     * overflow (when the input is greater than largest uint56).
     *
     * Counterpart to Solidity's `uint56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toUint56(uint256 value) internal pure returns (uint56) {
        if (value > type(uint56).max) {
            revert SafeCastOverflowedUintDowncast(56, value);
        }
        return uint56(value);
    }

    /**
     * @dev Returns the downcasted uint48 from uint256, reverting on
     * overflow (when the input is greater than largest uint48).
     *
     * Counterpart to Solidity's `uint48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toUint48(uint256 value) internal pure returns (uint48) {
        if (value > type(uint48).max) {
            revert SafeCastOverflowedUintDowncast(48, value);
        }
        return uint48(value);
    }

    /**
     * @dev Returns the downcasted uint40 from uint256, reverting on
     * overflow (when the input is greater than largest uint40).
     *
     * Counterpart to Solidity's `uint40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toUint40(uint256 value) internal pure returns (uint40) {
        if (value > type(uint40).max) {
            revert SafeCastOverflowedUintDowncast(40, value);
        }
        return uint40(value);
    }

    /**
     * @dev Returns the downcasted uint32 from uint256, reverting on
     * overflow (when the input is greater than largest uint32).
     *
     * Counterpart to Solidity's `uint32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toUint32(uint256 value) internal pure returns (uint32) {
        if (value > type(uint32).max) {
            revert SafeCastOverflowedUintDowncast(32, value);
        }
        return uint32(value);
    }

    /**
     * @dev Returns the downcasted uint24 from uint256, reverting on
     * overflow (when the input is greater than largest uint24).
     *
     * Counterpart to Solidity's `uint24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toUint24(uint256 value) internal pure returns (uint24) {
        if (value > type(uint24).max) {
            revert SafeCastOverflowedUintDowncast(24, value);
        }
        return uint24(value);
    }

    /**
     * @dev Returns the downcasted uint16 from uint256, reverting on
     * overflow (when the input is greater than largest uint16).
     *
     * Counterpart to Solidity's `uint16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toUint16(uint256 value) internal pure returns (uint16) {
        if (value > type(uint16).max) {
            revert SafeCastOverflowedUintDowncast(16, value);
        }
        return uint16(value);
    }

    /**
     * @dev Returns the downcasted uint8 from uint256, reverting on
     * overflow (when the input is greater than largest uint8).
     *
     * Counterpart to Solidity's `uint8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toUint8(uint256 value) internal pure returns (uint8) {
        if (value > type(uint8).max) {
            revert SafeCastOverflowedUintDowncast(8, value);
        }
        return uint8(value);
    }

    /**
     * @dev Converts a signed int256 into an unsigned uint256.
     *
     * Requirements:
     *
     * - input must be greater than or equal to 0.
     */
    function toUint256(int256 value) internal pure returns (uint256) {
        if (value < 0) {
            revert SafeCastOverflowedIntToUint(value);
        }
        return uint256(value);
    }

    /**
     * @dev Returns the downcasted int248 from int256, reverting on
     * overflow (when the input is less than smallest int248 or
     * greater than largest int248).
     *
     * Counterpart to Solidity's `int248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toInt248(int256 value) internal pure returns (int248 downcasted) {
        downcasted = int248(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(248, value);
        }
    }

    /**
     * @dev Returns the downcasted int240 from int256, reverting on
     * overflow (when the input is less than smallest int240 or
     * greater than largest int240).
     *
     * Counterpart to Solidity's `int240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toInt240(int256 value) internal pure returns (int240 downcasted) {
        downcasted = int240(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(240, value);
        }
    }

    /**
     * @dev Returns the downcasted int232 from int256, reverting on
     * overflow (when the input is less than smallest int232 or
     * greater than largest int232).
     *
     * Counterpart to Solidity's `int232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toInt232(int256 value) internal pure returns (int232 downcasted) {
        downcasted = int232(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(232, value);
        }
    }

    /**
     * @dev Returns the downcasted int224 from int256, reverting on
     * overflow (when the input is less than smallest int224 or
     * greater than largest int224).
     *
     * Counterpart to Solidity's `int224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toInt224(int256 value) internal pure returns (int224 downcasted) {
        downcasted = int224(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(224, value);
        }
    }

    /**
     * @dev Returns the downcasted int216 from int256, reverting on
     * overflow (when the input is less than smallest int216 or
     * greater than largest int216).
     *
     * Counterpart to Solidity's `int216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toInt216(int256 value) internal pure returns (int216 downcasted) {
        downcasted = int216(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(216, value);
        }
    }

    /**
     * @dev Returns the downcasted int208 from int256, reverting on
     * overflow (when the input is less than smallest int208 or
     * greater than largest int208).
     *
     * Counterpart to Solidity's `int208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toInt208(int256 value) internal pure returns (int208 downcasted) {
        downcasted = int208(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(208, value);
        }
    }

    /**
     * @dev Returns the downcasted int200 from int256, reverting on
     * overflow (when the input is less than smallest int200 or
     * greater than largest int200).
     *
     * Counterpart to Solidity's `int200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toInt200(int256 value) internal pure returns (int200 downcasted) {
        downcasted = int200(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(200, value);
        }
    }

    /**
     * @dev Returns the downcasted int192 from int256, reverting on
     * overflow (when the input is less than smallest int192 or
     * greater than largest int192).
     *
     * Counterpart to Solidity's `int192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toInt192(int256 value) internal pure returns (int192 downcasted) {
        downcasted = int192(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(192, value);
        }
    }

    /**
     * @dev Returns the downcasted int184 from int256, reverting on
     * overflow (when the input is less than smallest int184 or
     * greater than largest int184).
     *
     * Counterpart to Solidity's `int184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toInt184(int256 value) internal pure returns (int184 downcasted) {
        downcasted = int184(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(184, value);
        }
    }

    /**
     * @dev Returns the downcasted int176 from int256, reverting on
     * overflow (when the input is less than smallest int176 or
     * greater than largest int176).
     *
     * Counterpart to Solidity's `int176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toInt176(int256 value) internal pure returns (int176 downcasted) {
        downcasted = int176(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(176, value);
        }
    }

    /**
     * @dev Returns the downcasted int168 from int256, reverting on
     * overflow (when the input is less than smallest int168 or
     * greater than largest int168).
     *
     * Counterpart to Solidity's `int168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toInt168(int256 value) internal pure returns (int168 downcasted) {
        downcasted = int168(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(168, value);
        }
    }

    /**
     * @dev Returns the downcasted int160 from int256, reverting on
     * overflow (when the input is less than smallest int160 or
     * greater than largest int160).
     *
     * Counterpart to Solidity's `int160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toInt160(int256 value) internal pure returns (int160 downcasted) {
        downcasted = int160(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(160, value);
        }
    }

    /**
     * @dev Returns the downcasted int152 from int256, reverting on
     * overflow (when the input is less than smallest int152 or
     * greater than largest int152).
     *
     * Counterpart to Solidity's `int152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toInt152(int256 value) internal pure returns (int152 downcasted) {
        downcasted = int152(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(152, value);
        }
    }

    /**
     * @dev Returns the downcasted int144 from int256, reverting on
     * overflow (when the input is less than smallest int144 or
     * greater than largest int144).
     *
     * Counterpart to Solidity's `int144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toInt144(int256 value) internal pure returns (int144 downcasted) {
        downcasted = int144(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(144, value);
        }
    }

    /**
     * @dev Returns the downcasted int136 from int256, reverting on
     * overflow (when the input is less than smallest int136 or
     * greater than largest int136).
     *
     * Counterpart to Solidity's `int136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toInt136(int256 value) internal pure returns (int136 downcasted) {
        downcasted = int136(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(136, value);
        }
    }

    /**
     * @dev Returns the downcasted int128 from int256, reverting on
     * overflow (when the input is less than smallest int128 or
     * greater than largest int128).
     *
     * Counterpart to Solidity's `int128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toInt128(int256 value) internal pure returns (int128 downcasted) {
        downcasted = int128(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(128, value);
        }
    }

    /**
     * @dev Returns the downcasted int120 from int256, reverting on
     * overflow (when the input is less than smallest int120 or
     * greater than largest int120).
     *
     * Counterpart to Solidity's `int120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toInt120(int256 value) internal pure returns (int120 downcasted) {
        downcasted = int120(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(120, value);
        }
    }

    /**
     * @dev Returns the downcasted int112 from int256, reverting on
     * overflow (when the input is less than smallest int112 or
     * greater than largest int112).
     *
     * Counterpart to Solidity's `int112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toInt112(int256 value) internal pure returns (int112 downcasted) {
        downcasted = int112(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(112, value);
        }
    }

    /**
     * @dev Returns the downcasted int104 from int256, reverting on
     * overflow (when the input is less than smallest int104 or
     * greater than largest int104).
     *
     * Counterpart to Solidity's `int104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toInt104(int256 value) internal pure returns (int104 downcasted) {
        downcasted = int104(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(104, value);
        }
    }

    /**
     * @dev Returns the downcasted int96 from int256, reverting on
     * overflow (when the input is less than smallest int96 or
     * greater than largest int96).
     *
     * Counterpart to Solidity's `int96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toInt96(int256 value) internal pure returns (int96 downcasted) {
        downcasted = int96(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(96, value);
        }
    }

    /**
     * @dev Returns the downcasted int88 from int256, reverting on
     * overflow (when the input is less than smallest int88 or
     * greater than largest int88).
     *
     * Counterpart to Solidity's `int88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toInt88(int256 value) internal pure returns (int88 downcasted) {
        downcasted = int88(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(88, value);
        }
    }

    /**
     * @dev Returns the downcasted int80 from int256, reverting on
     * overflow (when the input is less than smallest int80 or
     * greater than largest int80).
     *
     * Counterpart to Solidity's `int80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toInt80(int256 value) internal pure returns (int80 downcasted) {
        downcasted = int80(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(80, value);
        }
    }

    /**
     * @dev Returns the downcasted int72 from int256, reverting on
     * overflow (when the input is less than smallest int72 or
     * greater than largest int72).
     *
     * Counterpart to Solidity's `int72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toInt72(int256 value) internal pure returns (int72 downcasted) {
        downcasted = int72(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(72, value);
        }
    }

    /**
     * @dev Returns the downcasted int64 from int256, reverting on
     * overflow (when the input is less than smallest int64 or
     * greater than largest int64).
     *
     * Counterpart to Solidity's `int64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toInt64(int256 value) internal pure returns (int64 downcasted) {
        downcasted = int64(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(64, value);
        }
    }

    /**
     * @dev Returns the downcasted int56 from int256, reverting on
     * overflow (when the input is less than smallest int56 or
     * greater than largest int56).
     *
     * Counterpart to Solidity's `int56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toInt56(int256 value) internal pure returns (int56 downcasted) {
        downcasted = int56(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(56, value);
        }
    }

    /**
     * @dev Returns the downcasted int48 from int256, reverting on
     * overflow (when the input is less than smallest int48 or
     * greater than largest int48).
     *
     * Counterpart to Solidity's `int48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toInt48(int256 value) internal pure returns (int48 downcasted) {
        downcasted = int48(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(48, value);
        }
    }

    /**
     * @dev Returns the downcasted int40 from int256, reverting on
     * overflow (when the input is less than smallest int40 or
     * greater than largest int40).
     *
     * Counterpart to Solidity's `int40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toInt40(int256 value) internal pure returns (int40 downcasted) {
        downcasted = int40(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(40, value);
        }
    }

    /**
     * @dev Returns the downcasted int32 from int256, reverting on
     * overflow (when the input is less than smallest int32 or
     * greater than largest int32).
     *
     * Counterpart to Solidity's `int32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toInt32(int256 value) internal pure returns (int32 downcasted) {
        downcasted = int32(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(32, value);
        }
    }

    /**
     * @dev Returns the downcasted int24 from int256, reverting on
     * overflow (when the input is less than smallest int24 or
     * greater than largest int24).
     *
     * Counterpart to Solidity's `int24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toInt24(int256 value) internal pure returns (int24 downcasted) {
        downcasted = int24(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(24, value);
        }
    }

    /**
     * @dev Returns the downcasted int16 from int256, reverting on
     * overflow (when the input is less than smallest int16 or
     * greater than largest int16).
     *
     * Counterpart to Solidity's `int16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toInt16(int256 value) internal pure returns (int16 downcasted) {
        downcasted = int16(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(16, value);
        }
    }

    /**
     * @dev Returns the downcasted int8 from int256, reverting on
     * overflow (when the input is less than smallest int8 or
     * greater than largest int8).
     *
     * Counterpart to Solidity's `int8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toInt8(int256 value) internal pure returns (int8 downcasted) {
        downcasted = int8(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(8, value);
        }
    }

    /**
     * @dev Converts an unsigned uint256 into a signed int256.
     *
     * Requirements:
     *
     * - input must be less than or equal to maxInt256.
     */
    function toInt256(uint256 value) internal pure returns (int256) {
        // Note: Unsafe cast below is okay because `type(int256).max` is guaranteed to be positive
        if (value > uint256(type(int256).max)) {
            revert SafeCastOverflowedUintToInt(value);
        }
        return int256(value);
    }

    /**
     * @dev Cast a boolean (false or true) to a uint256 (0 or 1) with no jump.
     */
    function toUint(bool b) internal pure returns (uint256 u) {
        assembly ("memory-safe") {
            u := iszero(iszero(b))
        }
    }
}


// File @openzeppelin/contracts/utils/Panic.sol@v5.4.0

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/Panic.sol)

pragma solidity ^0.8.20;

/**
 * @dev Helper library for emitting standardized panic codes.
 *
 * ```solidity
 * contract Example {
 *      using Panic for uint256;
 *
 *      // Use any of the declared internal constants
 *      function foo() { Panic.GENERIC.panic(); }
 *
 *      // Alternatively
 *      function foo() { Panic.panic(Panic.GENERIC); }
 * }
 * ```
 *
 * Follows the list from https://github.com/ethereum/solidity/blob/v0.8.24/libsolutil/ErrorCodes.h[libsolutil].
 *
 * _Available since v5.1._
 */
// slither-disable-next-line unused-state
library Panic {
    /// @dev generic / unspecified error
    uint256 internal constant GENERIC = 0x00;
    /// @dev used by the assert() builtin
    uint256 internal constant ASSERT = 0x01;
    /// @dev arithmetic underflow or overflow
    uint256 internal constant UNDER_OVERFLOW = 0x11;
    /// @dev division or modulo by zero
    uint256 internal constant DIVISION_BY_ZERO = 0x12;
    /// @dev enum conversion error
    uint256 internal constant ENUM_CONVERSION_ERROR = 0x21;
    /// @dev invalid encoding in storage
    uint256 internal constant STORAGE_ENCODING_ERROR = 0x22;
    /// @dev empty array pop
    uint256 internal constant EMPTY_ARRAY_POP = 0x31;
    /// @dev array out of bounds access
    uint256 internal constant ARRAY_OUT_OF_BOUNDS = 0x32;
    /// @dev resource error (too large allocation or too large array)
    uint256 internal constant RESOURCE_ERROR = 0x41;
    /// @dev calling invalid internal function
    uint256 internal constant INVALID_INTERNAL_FUNCTION = 0x51;

    /// @dev Reverts with a panic code. Recommended to use with
    /// the internal constants with predefined codes.
    function panic(uint256 code) internal pure {
        assembly ("memory-safe") {
            mstore(0x00, 0x4e487b71)
            mstore(0x20, code)
            revert(0x1c, 0x24)
        }
    }
}


// File @openzeppelin/contracts/utils/math/Math.sol@v5.4.0

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.3.0) (utils/math/Math.sol)

pragma solidity ^0.8.20;


/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    enum Rounding {
        Floor, // Toward negative infinity
        Ceil, // Toward positive infinity
        Trunc, // Toward zero
        Expand // Away from zero
    }

    /**
     * @dev Return the 512-bit addition of two uint256.
     *
     * The result is stored in two 256 variables such that sum = high * 2²⁵⁶ + low.
     */
    function add512(uint256 a, uint256 b) internal pure returns (uint256 high, uint256 low) {
        assembly ("memory-safe") {
            low := add(a, b)
            high := lt(low, a)
        }
    }

    /**
     * @dev Return the 512-bit multiplication of two uint256.
     *
     * The result is stored in two 256 variables such that product = high * 2²⁵⁶ + low.
     */
    function mul512(uint256 a, uint256 b) internal pure returns (uint256 high, uint256 low) {
        // 512-bit multiply [high low] = x * y. Compute the product mod 2²⁵⁶ and mod 2²⁵⁶ - 1, then use
        // the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256
        // variables such that product = high * 2²⁵⁶ + low.
        assembly ("memory-safe") {
            let mm := mulmod(a, b, not(0))
            low := mul(a, b)
            high := sub(sub(mm, low), lt(mm, low))
        }
    }

    /**
     * @dev Returns the addition of two unsigned integers, with a success flag (no overflow).
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a + b;
            success = c >= a;
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, with a success flag (no overflow).
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a - b;
            success = c <= a;
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with a success flag (no overflow).
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a * b;
            assembly ("memory-safe") {
                // Only true when the multiplication doesn't overflow
                // (c / a == b) || (a == 0)
                success := or(eq(div(c, a), b), iszero(a))
            }
            // equivalent to: success ? c : 0
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the division of two unsigned integers, with a success flag (no division by zero).
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            success = b > 0;
            assembly ("memory-safe") {
                // The `DIV` opcode returns zero when the denominator is 0.
                result := div(a, b)
            }
        }
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a success flag (no division by zero).
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            success = b > 0;
            assembly ("memory-safe") {
                // The `MOD` opcode returns zero when the denominator is 0.
                result := mod(a, b)
            }
        }
    }

    /**
     * @dev Unsigned saturating addition, bounds to `2²⁵⁶ - 1` instead of overflowing.
     */
    function saturatingAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        (bool success, uint256 result) = tryAdd(a, b);
        return ternary(success, result, type(uint256).max);
    }

    /**
     * @dev Unsigned saturating subtraction, bounds to zero instead of overflowing.
     */
    function saturatingSub(uint256 a, uint256 b) internal pure returns (uint256) {
        (, uint256 result) = trySub(a, b);
        return result;
    }

    /**
     * @dev Unsigned saturating multiplication, bounds to `2²⁵⁶ - 1` instead of overflowing.
     */
    function saturatingMul(uint256 a, uint256 b) internal pure returns (uint256) {
        (bool success, uint256 result) = tryMul(a, b);
        return ternary(success, result, type(uint256).max);
    }

    /**
     * @dev Branchless ternary evaluation for `a ? b : c`. Gas costs are constant.
     *
     * IMPORTANT: This function may reduce bytecode size and consume less gas when used standalone.
     * However, the compiler may optimize Solidity ternary operations (i.e. `a ? b : c`) to only compute
     * one branch when needed, making this function more expensive.
     */
    function ternary(bool condition, uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            // branchless ternary works because:
            // b ^ (a ^ b) == a
            // b ^ 0 == b
            return b ^ ((a ^ b) * SafeCast.toUint(condition));
        }
    }

    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return ternary(a > b, a, b);
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return ternary(a < b, a, b);
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b) / 2 can overflow.
        return (a & b) + (a ^ b) / 2;
    }

    /**
     * @dev Returns the ceiling of the division of two numbers.
     *
     * This differs from standard division with `/` in that it rounds towards infinity instead
     * of rounding towards zero.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) {
            // Guarantee the same behavior as in a regular Solidity division.
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }

        // The following calculation ensures accurate ceiling division without overflow.
        // Since a is non-zero, (a - 1) / b will not overflow.
        // The largest possible result occurs when (a - 1) / b is type(uint256).max,
        // but the largest value we can obtain is type(uint256).max - 1, which happens
        // when a = type(uint256).max and b = 1.
        unchecked {
            return SafeCast.toUint(a > 0) * ((a - 1) / b + 1);
        }
    }

    /**
     * @dev Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or
     * denominator == 0.
     *
     * Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv) with further edits by
     * Uniswap Labs also under MIT license.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            (uint256 high, uint256 low) = mul512(x, y);

            // Handle non-overflow cases, 256 by 256 division.
            if (high == 0) {
                // Solidity will revert if denominator == 0, unlike the div opcode on its own.
                // The surrounding unchecked block does not change this fact.
                // See https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic.
                return low / denominator;
            }

            // Make sure the result is less than 2²⁵⁶. Also prevents denominator == 0.
            if (denominator <= high) {
                Panic.panic(ternary(denominator == 0, Panic.DIVISION_BY_ZERO, Panic.UNDER_OVERFLOW));
            }

            ///////////////////////////////////////////////
            // 512 by 256 division.
            ///////////////////////////////////////////////

            // Make division exact by subtracting the remainder from [high low].
            uint256 remainder;
            assembly ("memory-safe") {
                // Compute remainder using mulmod.
                remainder := mulmod(x, y, denominator)

                // Subtract 256 bit number from 512 bit number.
                high := sub(high, gt(remainder, low))
                low := sub(low, remainder)
            }

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator.
            // Always >= 1. See https://cs.stackexchange.com/q/138556/92363.

            uint256 twos = denominator & (0 - denominator);
            assembly ("memory-safe") {
                // Divide denominator by twos.
                denominator := div(denominator, twos)

                // Divide [high low] by twos.
                low := div(low, twos)

                // Flip twos such that it is 2²⁵⁶ / twos. If twos is zero, then it becomes one.
                twos := add(div(sub(0, twos), twos), 1)
            }

            // Shift in bits from high into low.
            low |= high * twos;

            // Invert denominator mod 2²⁵⁶. Now that denominator is an odd number, it has an inverse modulo 2²⁵⁶ such
            // that denominator * inv ≡ 1 mod 2²⁵⁶. Compute the inverse by starting with a seed that is correct for
            // four bits. That is, denominator * inv ≡ 1 mod 2⁴.
            uint256 inverse = (3 * denominator) ^ 2;

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also
            // works in modular arithmetic, doubling the correct bits in each step.
            inverse *= 2 - denominator * inverse; // inverse mod 2⁸
            inverse *= 2 - denominator * inverse; // inverse mod 2¹⁶
            inverse *= 2 - denominator * inverse; // inverse mod 2³²
            inverse *= 2 - denominator * inverse; // inverse mod 2⁶⁴
            inverse *= 2 - denominator * inverse; // inverse mod 2¹²⁸
            inverse *= 2 - denominator * inverse; // inverse mod 2²⁵⁶

            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.
            // This will give us the correct result modulo 2²⁵⁶. Since the preconditions guarantee that the outcome is
            // less than 2²⁵⁶, this is the final result. We don't need to compute the high bits of the result and high
            // is no longer required.
            result = low * inverse;
            return result;
        }
    }

    /**
     * @dev Calculates x * y / denominator with full precision, following the selected rounding direction.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        return mulDiv(x, y, denominator) + SafeCast.toUint(unsignedRoundsUp(rounding) && mulmod(x, y, denominator) > 0);
    }

    /**
     * @dev Calculates floor(x * y >> n) with full precision. Throws if result overflows a uint256.
     */
    function mulShr(uint256 x, uint256 y, uint8 n) internal pure returns (uint256 result) {
        unchecked {
            (uint256 high, uint256 low) = mul512(x, y);
            if (high >= 1 << n) {
                Panic.panic(Panic.UNDER_OVERFLOW);
            }
            return (high << (256 - n)) | (low >> n);
        }
    }

    /**
     * @dev Calculates x * y >> n with full precision, following the selected rounding direction.
     */
    function mulShr(uint256 x, uint256 y, uint8 n, Rounding rounding) internal pure returns (uint256) {
        return mulShr(x, y, n) + SafeCast.toUint(unsignedRoundsUp(rounding) && mulmod(x, y, 1 << n) > 0);
    }

    /**
     * @dev Calculate the modular multiplicative inverse of a number in Z/nZ.
     *
     * If n is a prime, then Z/nZ is a field. In that case all elements are inversible, except 0.
     * If n is not a prime, then Z/nZ is not a field, and some elements might not be inversible.
     *
     * If the input value is not inversible, 0 is returned.
     *
     * NOTE: If you know for sure that n is (big) a prime, it may be cheaper to use Fermat's little theorem and get the
     * inverse using `Math.modExp(a, n - 2, n)`. See {invModPrime}.
     */
    function invMod(uint256 a, uint256 n) internal pure returns (uint256) {
        unchecked {
            if (n == 0) return 0;

            // The inverse modulo is calculated using the Extended Euclidean Algorithm (iterative version)
            // Used to compute integers x and y such that: ax + ny = gcd(a, n).
            // When the gcd is 1, then the inverse of a modulo n exists and it's x.
            // ax + ny = 1
            // ax = 1 + (-y)n
            // ax ≡ 1 (mod n) # x is the inverse of a modulo n

            // If the remainder is 0 the gcd is n right away.
            uint256 remainder = a % n;
            uint256 gcd = n;

            // Therefore the initial coefficients are:
            // ax + ny = gcd(a, n) = n
            // 0a + 1n = n
            int256 x = 0;
            int256 y = 1;

            while (remainder != 0) {
                uint256 quotient = gcd / remainder;

                (gcd, remainder) = (
                    // The old remainder is the next gcd to try.
                    remainder,
                    // Compute the next remainder.
                    // Can't overflow given that (a % gcd) * (gcd // (a % gcd)) <= gcd
                    // where gcd is at most n (capped to type(uint256).max)
                    gcd - remainder * quotient
                );

                (x, y) = (
                    // Increment the coefficient of a.
                    y,
                    // Decrement the coefficient of n.
                    // Can overflow, but the result is casted to uint256 so that the
                    // next value of y is "wrapped around" to a value between 0 and n - 1.
                    x - y * int256(quotient)
                );
            }

            if (gcd != 1) return 0; // No inverse exists.
            return ternary(x < 0, n - uint256(-x), uint256(x)); // Wrap the result if it's negative.
        }
    }

    /**
     * @dev Variant of {invMod}. More efficient, but only works if `p` is known to be a prime greater than `2`.
     *
     * From https://en.wikipedia.org/wiki/Fermat%27s_little_theorem[Fermat's little theorem], we know that if p is
     * prime, then `a**(p-1) ≡ 1 mod p`. As a consequence, we have `a * a**(p-2) ≡ 1 mod p`, which means that
     * `a**(p-2)` is the modular multiplicative inverse of a in Fp.
     *
     * NOTE: this function does NOT check that `p` is a prime greater than `2`.
     */
    function invModPrime(uint256 a, uint256 p) internal view returns (uint256) {
        unchecked {
            return Math.modExp(a, p - 2, p);
        }
    }

    /**
     * @dev Returns the modular exponentiation of the specified base, exponent and modulus (b ** e % m)
     *
     * Requirements:
     * - modulus can't be zero
     * - underlying staticcall to precompile must succeed
     *
     * IMPORTANT: The result is only valid if the underlying call succeeds. When using this function, make
     * sure the chain you're using it on supports the precompiled contract for modular exponentiation
     * at address 0x05 as specified in https://eips.ethereum.org/EIPS/eip-198[EIP-198]. Otherwise,
     * the underlying function will succeed given the lack of a revert, but the result may be incorrectly
     * interpreted as 0.
     */
    function modExp(uint256 b, uint256 e, uint256 m) internal view returns (uint256) {
        (bool success, uint256 result) = tryModExp(b, e, m);
        if (!success) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        return result;
    }

    /**
     * @dev Returns the modular exponentiation of the specified base, exponent and modulus (b ** e % m).
     * It includes a success flag indicating if the operation succeeded. Operation will be marked as failed if trying
     * to operate modulo 0 or if the underlying precompile reverted.
     *
     * IMPORTANT: The result is only valid if the success flag is true. When using this function, make sure the chain
     * you're using it on supports the precompiled contract for modular exponentiation at address 0x05 as specified in
     * https://eips.ethereum.org/EIPS/eip-198[EIP-198]. Otherwise, the underlying function will succeed given the lack
     * of a revert, but the result may be incorrectly interpreted as 0.
     */
    function tryModExp(uint256 b, uint256 e, uint256 m) internal view returns (bool success, uint256 result) {
        if (m == 0) return (false, 0);
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            // | Offset    | Content    | Content (Hex)                                                      |
            // |-----------|------------|--------------------------------------------------------------------|
            // | 0x00:0x1f | size of b  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x20:0x3f | size of e  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x40:0x5f | size of m  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x60:0x7f | value of b | 0x<.............................................................b> |
            // | 0x80:0x9f | value of e | 0x<.............................................................e> |
            // | 0xa0:0xbf | value of m | 0x<.............................................................m> |
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), 0x20)
            mstore(add(ptr, 0x40), 0x20)
            mstore(add(ptr, 0x60), b)
            mstore(add(ptr, 0x80), e)
            mstore(add(ptr, 0xa0), m)

            // Given the result < m, it's guaranteed to fit in 32 bytes,
            // so we can use the memory scratch space located at offset 0.
            success := staticcall(gas(), 0x05, ptr, 0xc0, 0x00, 0x20)
            result := mload(0x00)
        }
    }

    /**
     * @dev Variant of {modExp} that supports inputs of arbitrary length.
     */
    function modExp(bytes memory b, bytes memory e, bytes memory m) internal view returns (bytes memory) {
        (bool success, bytes memory result) = tryModExp(b, e, m);
        if (!success) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        return result;
    }

    /**
     * @dev Variant of {tryModExp} that supports inputs of arbitrary length.
     */
    function tryModExp(
        bytes memory b,
        bytes memory e,
        bytes memory m
    ) internal view returns (bool success, bytes memory result) {
        if (_zeroBytes(m)) return (false, new bytes(0));

        uint256 mLen = m.length;

        // Encode call args in result and move the free memory pointer
        result = abi.encodePacked(b.length, e.length, mLen, b, e, m);

        assembly ("memory-safe") {
            let dataPtr := add(result, 0x20)
            // Write result on top of args to avoid allocating extra memory.
            success := staticcall(gas(), 0x05, dataPtr, mload(result), dataPtr, mLen)
            // Overwrite the length.
            // result.length > returndatasize() is guaranteed because returndatasize() == m.length
            mstore(result, mLen)
            // Set the memory pointer after the returned data.
            mstore(0x40, add(dataPtr, mLen))
        }
    }

    /**
     * @dev Returns whether the provided byte array is zero.
     */
    function _zeroBytes(bytes memory byteArray) private pure returns (bool) {
        for (uint256 i = 0; i < byteArray.length; ++i) {
            if (byteArray[i] != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded
     * towards zero.
     *
     * This method is based on Newton's method for computing square roots; the algorithm is restricted to only
     * using integer operations.
     */
    function sqrt(uint256 a) internal pure returns (uint256) {
        unchecked {
            // Take care of easy edge cases when a == 0 or a == 1
            if (a <= 1) {
                return a;
            }

            // In this function, we use Newton's method to get a root of `f(x) := x² - a`. It involves building a
            // sequence x_n that converges toward sqrt(a). For each iteration x_n, we also define the error between
            // the current value as `ε_n = | x_n - sqrt(a) |`.
            //
            // For our first estimation, we consider `e` the smallest power of 2 which is bigger than the square root
            // of the target. (i.e. `2**(e-1) ≤ sqrt(a) < 2**e`). We know that `e ≤ 128` because `(2¹²⁸)² = 2²⁵⁶` is
            // bigger than any uint256.
            //
            // By noticing that
            // `2**(e-1) ≤ sqrt(a) < 2**e → (2**(e-1))² ≤ a < (2**e)² → 2**(2*e-2) ≤ a < 2**(2*e)`
            // we can deduce that `e - 1` is `log2(a) / 2`. We can thus compute `x_n = 2**(e-1)` using a method similar
            // to the msb function.
            uint256 aa = a;
            uint256 xn = 1;

            if (aa >= (1 << 128)) {
                aa >>= 128;
                xn <<= 64;
            }
            if (aa >= (1 << 64)) {
                aa >>= 64;
                xn <<= 32;
            }
            if (aa >= (1 << 32)) {
                aa >>= 32;
                xn <<= 16;
            }
            if (aa >= (1 << 16)) {
                aa >>= 16;
                xn <<= 8;
            }
            if (aa >= (1 << 8)) {
                aa >>= 8;
                xn <<= 4;
            }
            if (aa >= (1 << 4)) {
                aa >>= 4;
                xn <<= 2;
            }
            if (aa >= (1 << 2)) {
                xn <<= 1;
            }

            // We now have x_n such that `x_n = 2**(e-1) ≤ sqrt(a) < 2**e = 2 * x_n`. This implies ε_n ≤ 2**(e-1).
            //
            // We can refine our estimation by noticing that the middle of that interval minimizes the error.
            // If we move x_n to equal 2**(e-1) + 2**(e-2), then we reduce the error to ε_n ≤ 2**(e-2).
            // This is going to be our x_0 (and ε_0)
            xn = (3 * xn) >> 1; // ε_0 := | x_0 - sqrt(a) | ≤ 2**(e-2)

            // From here, Newton's method give us:
            // x_{n+1} = (x_n + a / x_n) / 2
            //
            // One should note that:
            // x_{n+1}² - a = ((x_n + a / x_n) / 2)² - a
            //              = ((x_n² + a) / (2 * x_n))² - a
            //              = (x_n⁴ + 2 * a * x_n² + a²) / (4 * x_n²) - a
            //              = (x_n⁴ + 2 * a * x_n² + a² - 4 * a * x_n²) / (4 * x_n²)
            //              = (x_n⁴ - 2 * a * x_n² + a²) / (4 * x_n²)
            //              = (x_n² - a)² / (2 * x_n)²
            //              = ((x_n² - a) / (2 * x_n))²
            //              ≥ 0
            // Which proves that for all n ≥ 1, sqrt(a) ≤ x_n
            //
            // This gives us the proof of quadratic convergence of the sequence:
            // ε_{n+1} = | x_{n+1} - sqrt(a) |
            //         = | (x_n + a / x_n) / 2 - sqrt(a) |
            //         = | (x_n² + a - 2*x_n*sqrt(a)) / (2 * x_n) |
            //         = | (x_n - sqrt(a))² / (2 * x_n) |
            //         = | ε_n² / (2 * x_n) |
            //         = ε_n² / | (2 * x_n) |
            //
            // For the first iteration, we have a special case where x_0 is known:
            // ε_1 = ε_0² / | (2 * x_0) |
            //     ≤ (2**(e-2))² / (2 * (2**(e-1) + 2**(e-2)))
            //     ≤ 2**(2*e-4) / (3 * 2**(e-1))
            //     ≤ 2**(e-3) / 3
            //     ≤ 2**(e-3-log2(3))
            //     ≤ 2**(e-4.5)
            //
            // For the following iterations, we use the fact that, 2**(e-1) ≤ sqrt(a) ≤ x_n:
            // ε_{n+1} = ε_n² / | (2 * x_n) |
            //         ≤ (2**(e-k))² / (2 * 2**(e-1))
            //         ≤ 2**(2*e-2*k) / 2**e
            //         ≤ 2**(e-2*k)
            xn = (xn + a / xn) >> 1; // ε_1 := | x_1 - sqrt(a) | ≤ 2**(e-4.5)  -- special case, see above
            xn = (xn + a / xn) >> 1; // ε_2 := | x_2 - sqrt(a) | ≤ 2**(e-9)    -- general case with k = 4.5
            xn = (xn + a / xn) >> 1; // ε_3 := | x_3 - sqrt(a) | ≤ 2**(e-18)   -- general case with k = 9
            xn = (xn + a / xn) >> 1; // ε_4 := | x_4 - sqrt(a) | ≤ 2**(e-36)   -- general case with k = 18
            xn = (xn + a / xn) >> 1; // ε_5 := | x_5 - sqrt(a) | ≤ 2**(e-72)   -- general case with k = 36
            xn = (xn + a / xn) >> 1; // ε_6 := | x_6 - sqrt(a) | ≤ 2**(e-144)  -- general case with k = 72

            // Because e ≤ 128 (as discussed during the first estimation phase), we know have reached a precision
            // ε_6 ≤ 2**(e-144) < 1. Given we're operating on integers, then we can ensure that xn is now either
            // sqrt(a) or sqrt(a) + 1.
            return xn - SafeCast.toUint(xn > a / xn);
        }
    }

    /**
     * @dev Calculates sqrt(a), following the selected rounding direction.
     */
    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = sqrt(a);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && result * result < a);
        }
    }

    /**
     * @dev Return the log in base 2 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log2(uint256 x) internal pure returns (uint256 r) {
        // If value has upper 128 bits set, log2 result is at least 128
        r = SafeCast.toUint(x > 0xffffffffffffffffffffffffffffffff) << 7;
        // If upper 64 bits of 128-bit half set, add 64 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffffffffffff) << 6;
        // If upper 32 bits of 64-bit half set, add 32 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffff) << 5;
        // If upper 16 bits of 32-bit half set, add 16 to result
        r |= SafeCast.toUint((x >> r) > 0xffff) << 4;
        // If upper 8 bits of 16-bit half set, add 8 to result
        r |= SafeCast.toUint((x >> r) > 0xff) << 3;
        // If upper 4 bits of 8-bit half set, add 4 to result
        r |= SafeCast.toUint((x >> r) > 0xf) << 2;

        // Shifts value right by the current result and use it as an index into this lookup table:
        //
        // | x (4 bits) |  index  | table[index] = MSB position |
        // |------------|---------|-----------------------------|
        // |    0000    |    0    |        table[0] = 0         |
        // |    0001    |    1    |        table[1] = 0         |
        // |    0010    |    2    |        table[2] = 1         |
        // |    0011    |    3    |        table[3] = 1         |
        // |    0100    |    4    |        table[4] = 2         |
        // |    0101    |    5    |        table[5] = 2         |
        // |    0110    |    6    |        table[6] = 2         |
        // |    0111    |    7    |        table[7] = 2         |
        // |    1000    |    8    |        table[8] = 3         |
        // |    1001    |    9    |        table[9] = 3         |
        // |    1010    |   10    |        table[10] = 3        |
        // |    1011    |   11    |        table[11] = 3        |
        // |    1100    |   12    |        table[12] = 3        |
        // |    1101    |   13    |        table[13] = 3        |
        // |    1110    |   14    |        table[14] = 3        |
        // |    1111    |   15    |        table[15] = 3        |
        //
        // The lookup table is represented as a 32-byte value with the MSB positions for 0-15 in the last 16 bytes.
        assembly ("memory-safe") {
            r := or(r, byte(shr(r, x), 0x0000010102020202030303030303030300000000000000000000000000000000))
        }
    }

    /**
     * @dev Return the log in base 2, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log2(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 1 << result < value);
        }
    }

    /**
     * @dev Return the log in base 10 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log10(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 10 ** result < value);
        }
    }

    /**
     * @dev Return the log in base 256 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     *
     * Adding one to the result gives the number of pairs of hex symbols needed to represent `value` as a hex string.
     */
    function log256(uint256 x) internal pure returns (uint256 r) {
        // If value has upper 128 bits set, log2 result is at least 128
        r = SafeCast.toUint(x > 0xffffffffffffffffffffffffffffffff) << 7;
        // If upper 64 bits of 128-bit half set, add 64 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffffffffffff) << 6;
        // If upper 32 bits of 64-bit half set, add 32 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffff) << 5;
        // If upper 16 bits of 32-bit half set, add 16 to result
        r |= SafeCast.toUint((x >> r) > 0xffff) << 4;
        // Add 1 if upper 8 bits of 16-bit half set, and divide accumulated result by 8
        return (r >> 3) | SafeCast.toUint((x >> r) > 0xff);
    }

    /**
     * @dev Return the log in base 256, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log256(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 1 << (result << 3) < value);
        }
    }

    /**
     * @dev Returns whether a provided rounding mode is considered rounding up for unsigned integers.
     */
    function unsignedRoundsUp(Rounding rounding) internal pure returns (bool) {
        return uint8(rounding) % 2 == 1;
    }
}


// File @openzeppelin/contracts/utils/math/SignedMath.sol@v5.4.0

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/math/SignedMath.sol)

pragma solidity ^0.8.20;

/**
 * @dev Standard signed math utilities missing in the Solidity language.
 */
library SignedMath {
    /**
     * @dev Branchless ternary evaluation for `a ? b : c`. Gas costs are constant.
     *
     * IMPORTANT: This function may reduce bytecode size and consume less gas when used standalone.
     * However, the compiler may optimize Solidity ternary operations (i.e. `a ? b : c`) to only compute
     * one branch when needed, making this function more expensive.
     */
    function ternary(bool condition, int256 a, int256 b) internal pure returns (int256) {
        unchecked {
            // branchless ternary works because:
            // b ^ (a ^ b) == a
            // b ^ 0 == b
            return b ^ ((a ^ b) * int256(SafeCast.toUint(condition)));
        }
    }

    /**
     * @dev Returns the largest of two signed numbers.
     */
    function max(int256 a, int256 b) internal pure returns (int256) {
        return ternary(a > b, a, b);
    }

    /**
     * @dev Returns the smallest of two signed numbers.
     */
    function min(int256 a, int256 b) internal pure returns (int256) {
        return ternary(a < b, a, b);
    }

    /**
     * @dev Returns the average of two signed numbers without overflow.
     * The result is rounded towards zero.
     */
    function average(int256 a, int256 b) internal pure returns (int256) {
        // Formula from the book "Hacker's Delight"
        int256 x = (a & b) + ((a ^ b) >> 1);
        return x + (int256(uint256(x) >> 255) & (a ^ b));
    }

    /**
     * @dev Returns the absolute unsigned value of a signed value.
     */
    function abs(int256 n) internal pure returns (uint256) {
        unchecked {
            // Formula from the "Bit Twiddling Hacks" by Sean Eron Anderson.
            // Since `n` is a signed integer, the generated bytecode will use the SAR opcode to perform the right shift,
            // taking advantage of the most significant (or "sign" bit) in two's complement representation.
            // This opcode adds new most significant bits set to the value of the previous most significant bit. As a result,
            // the mask will either be `bytes32(0)` (if n is positive) or `~bytes32(0)` (if n is negative).
            int256 mask = n >> 255;

            // A `bytes32(0)` mask leaves the input unchanged, while a `~bytes32(0)` mask complements it.
            return uint256((n + mask) ^ mask);
        }
    }
}


// File @openzeppelin/contracts/utils/Strings.sol@v5.4.0

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (utils/Strings.sol)

pragma solidity ^0.8.20;



/**
 * @dev String operations.
 */
library Strings {
    using SafeCast for *;

    bytes16 private constant HEX_DIGITS = "0123456789abcdef";
    uint8 private constant ADDRESS_LENGTH = 20;
    uint256 private constant SPECIAL_CHARS_LOOKUP =
        (1 << 0x08) | // backspace
            (1 << 0x09) | // tab
            (1 << 0x0a) | // newline
            (1 << 0x0c) | // form feed
            (1 << 0x0d) | // carriage return
            (1 << 0x22) | // double quote
            (1 << 0x5c); // backslash

    /**
     * @dev The `value` string doesn't fit in the specified `length`.
     */
    error StringsInsufficientHexLength(uint256 value, uint256 length);

    /**
     * @dev The string being parsed contains characters that are not in scope of the given base.
     */
    error StringsInvalidChar();

    /**
     * @dev The string being parsed is not a properly formatted address.
     */
    error StringsInvalidAddressFormat();

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        unchecked {
            uint256 length = Math.log10(value) + 1;
            string memory buffer = new string(length);
            uint256 ptr;
            assembly ("memory-safe") {
                ptr := add(add(buffer, 0x20), length)
            }
            while (true) {
                ptr--;
                assembly ("memory-safe") {
                    mstore8(ptr, byte(mod(value, 10), HEX_DIGITS))
                }
                value /= 10;
                if (value == 0) break;
            }
            return buffer;
        }
    }

    /**
     * @dev Converts a `int256` to its ASCII `string` decimal representation.
     */
    function toStringSigned(int256 value) internal pure returns (string memory) {
        return string.concat(value < 0 ? "-" : "", toString(SignedMath.abs(value)));
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        unchecked {
            return toHexString(value, Math.log256(value) + 1);
        }
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        uint256 localValue = value;
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = HEX_DIGITS[localValue & 0xf];
            localValue >>= 4;
        }
        if (localValue != 0) {
            revert StringsInsufficientHexLength(value, length);
        }
        return string(buffer);
    }

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal
     * representation.
     */
    function toHexString(address addr) internal pure returns (string memory) {
        return toHexString(uint256(uint160(addr)), ADDRESS_LENGTH);
    }

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its checksummed ASCII `string` hexadecimal
     * representation, according to EIP-55.
     */
    function toChecksumHexString(address addr) internal pure returns (string memory) {
        bytes memory buffer = bytes(toHexString(addr));

        // hash the hex part of buffer (skip length + 2 bytes, length 40)
        uint256 hashValue;
        assembly ("memory-safe") {
            hashValue := shr(96, keccak256(add(buffer, 0x22), 40))
        }

        for (uint256 i = 41; i > 1; --i) {
            // possible values for buffer[i] are 48 (0) to 57 (9) and 97 (a) to 102 (f)
            if (hashValue & 0xf > 7 && uint8(buffer[i]) > 96) {
                // case shift by xoring with 0x20
                buffer[i] ^= 0x20;
            }
            hashValue >>= 4;
        }
        return string(buffer);
    }

    /**
     * @dev Returns true if the two strings are equal.
     */
    function equal(string memory a, string memory b) internal pure returns (bool) {
        return bytes(a).length == bytes(b).length && keccak256(bytes(a)) == keccak256(bytes(b));
    }

    /**
     * @dev Parse a decimal string and returns the value as a `uint256`.
     *
     * Requirements:
     * - The string must be formatted as `[0-9]*`
     * - The result must fit into an `uint256` type
     */
    function parseUint(string memory input) internal pure returns (uint256) {
        return parseUint(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseUint-string} that parses a substring of `input` located between position `begin` (included) and
     * `end` (excluded).
     *
     * Requirements:
     * - The substring must be formatted as `[0-9]*`
     * - The result must fit into an `uint256` type
     */
    function parseUint(string memory input, uint256 begin, uint256 end) internal pure returns (uint256) {
        (bool success, uint256 value) = tryParseUint(input, begin, end);
        if (!success) revert StringsInvalidChar();
        return value;
    }

    /**
     * @dev Variant of {parseUint-string} that returns false if the parsing fails because of an invalid character.
     *
     * NOTE: This function will revert if the result does not fit in a `uint256`.
     */
    function tryParseUint(string memory input) internal pure returns (bool success, uint256 value) {
        return _tryParseUintUncheckedBounds(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseUint-string-uint256-uint256} that returns false if the parsing fails because of an invalid
     * character.
     *
     * NOTE: This function will revert if the result does not fit in a `uint256`.
     */
    function tryParseUint(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, uint256 value) {
        if (end > bytes(input).length || begin > end) return (false, 0);
        return _tryParseUintUncheckedBounds(input, begin, end);
    }

    /**
     * @dev Implementation of {tryParseUint-string-uint256-uint256} that does not check bounds. Caller should make sure that
     * `begin <= end <= input.length`. Other inputs would result in undefined behavior.
     */
    function _tryParseUintUncheckedBounds(
        string memory input,
        uint256 begin,
        uint256 end
    ) private pure returns (bool success, uint256 value) {
        bytes memory buffer = bytes(input);

        uint256 result = 0;
        for (uint256 i = begin; i < end; ++i) {
            uint8 chr = _tryParseChr(bytes1(_unsafeReadBytesOffset(buffer, i)));
            if (chr > 9) return (false, 0);
            result *= 10;
            result += chr;
        }
        return (true, result);
    }

    /**
     * @dev Parse a decimal string and returns the value as a `int256`.
     *
     * Requirements:
     * - The string must be formatted as `[-+]?[0-9]*`
     * - The result must fit in an `int256` type.
     */
    function parseInt(string memory input) internal pure returns (int256) {
        return parseInt(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseInt-string} that parses a substring of `input` located between position `begin` (included) and
     * `end` (excluded).
     *
     * Requirements:
     * - The substring must be formatted as `[-+]?[0-9]*`
     * - The result must fit in an `int256` type.
     */
    function parseInt(string memory input, uint256 begin, uint256 end) internal pure returns (int256) {
        (bool success, int256 value) = tryParseInt(input, begin, end);
        if (!success) revert StringsInvalidChar();
        return value;
    }

    /**
     * @dev Variant of {parseInt-string} that returns false if the parsing fails because of an invalid character or if
     * the result does not fit in a `int256`.
     *
     * NOTE: This function will revert if the absolute value of the result does not fit in a `uint256`.
     */
    function tryParseInt(string memory input) internal pure returns (bool success, int256 value) {
        return _tryParseIntUncheckedBounds(input, 0, bytes(input).length);
    }

    uint256 private constant ABS_MIN_INT256 = 2 ** 255;

    /**
     * @dev Variant of {parseInt-string-uint256-uint256} that returns false if the parsing fails because of an invalid
     * character or if the result does not fit in a `int256`.
     *
     * NOTE: This function will revert if the absolute value of the result does not fit in a `uint256`.
     */
    function tryParseInt(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, int256 value) {
        if (end > bytes(input).length || begin > end) return (false, 0);
        return _tryParseIntUncheckedBounds(input, begin, end);
    }

    /**
     * @dev Implementation of {tryParseInt-string-uint256-uint256} that does not check bounds. Caller should make sure that
     * `begin <= end <= input.length`. Other inputs would result in undefined behavior.
     */
    function _tryParseIntUncheckedBounds(
        string memory input,
        uint256 begin,
        uint256 end
    ) private pure returns (bool success, int256 value) {
        bytes memory buffer = bytes(input);

        // Check presence of a negative sign.
        bytes1 sign = begin == end ? bytes1(0) : bytes1(_unsafeReadBytesOffset(buffer, begin)); // don't do out-of-bound (possibly unsafe) read if sub-string is empty
        bool positiveSign = sign == bytes1("+");
        bool negativeSign = sign == bytes1("-");
        uint256 offset = (positiveSign || negativeSign).toUint();

        (bool absSuccess, uint256 absValue) = tryParseUint(input, begin + offset, end);

        if (absSuccess && absValue < ABS_MIN_INT256) {
            return (true, negativeSign ? -int256(absValue) : int256(absValue));
        } else if (absSuccess && negativeSign && absValue == ABS_MIN_INT256) {
            return (true, type(int256).min);
        } else return (false, 0);
    }

    /**
     * @dev Parse a hexadecimal string (with or without "0x" prefix), and returns the value as a `uint256`.
     *
     * Requirements:
     * - The string must be formatted as `(0x)?[0-9a-fA-F]*`
     * - The result must fit in an `uint256` type.
     */
    function parseHexUint(string memory input) internal pure returns (uint256) {
        return parseHexUint(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseHexUint-string} that parses a substring of `input` located between position `begin` (included) and
     * `end` (excluded).
     *
     * Requirements:
     * - The substring must be formatted as `(0x)?[0-9a-fA-F]*`
     * - The result must fit in an `uint256` type.
     */
    function parseHexUint(string memory input, uint256 begin, uint256 end) internal pure returns (uint256) {
        (bool success, uint256 value) = tryParseHexUint(input, begin, end);
        if (!success) revert StringsInvalidChar();
        return value;
    }

    /**
     * @dev Variant of {parseHexUint-string} that returns false if the parsing fails because of an invalid character.
     *
     * NOTE: This function will revert if the result does not fit in a `uint256`.
     */
    function tryParseHexUint(string memory input) internal pure returns (bool success, uint256 value) {
        return _tryParseHexUintUncheckedBounds(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseHexUint-string-uint256-uint256} that returns false if the parsing fails because of an
     * invalid character.
     *
     * NOTE: This function will revert if the result does not fit in a `uint256`.
     */
    function tryParseHexUint(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, uint256 value) {
        if (end > bytes(input).length || begin > end) return (false, 0);
        return _tryParseHexUintUncheckedBounds(input, begin, end);
    }

    /**
     * @dev Implementation of {tryParseHexUint-string-uint256-uint256} that does not check bounds. Caller should make sure that
     * `begin <= end <= input.length`. Other inputs would result in undefined behavior.
     */
    function _tryParseHexUintUncheckedBounds(
        string memory input,
        uint256 begin,
        uint256 end
    ) private pure returns (bool success, uint256 value) {
        bytes memory buffer = bytes(input);

        // skip 0x prefix if present
        bool hasPrefix = (end > begin + 1) && bytes2(_unsafeReadBytesOffset(buffer, begin)) == bytes2("0x"); // don't do out-of-bound (possibly unsafe) read if sub-string is empty
        uint256 offset = hasPrefix.toUint() * 2;

        uint256 result = 0;
        for (uint256 i = begin + offset; i < end; ++i) {
            uint8 chr = _tryParseChr(bytes1(_unsafeReadBytesOffset(buffer, i)));
            if (chr > 15) return (false, 0);
            result *= 16;
            unchecked {
                // Multiplying by 16 is equivalent to a shift of 4 bits (with additional overflow check).
                // This guarantees that adding a value < 16 will not cause an overflow, hence the unchecked.
                result += chr;
            }
        }
        return (true, result);
    }

    /**
     * @dev Parse a hexadecimal string (with or without "0x" prefix), and returns the value as an `address`.
     *
     * Requirements:
     * - The string must be formatted as `(0x)?[0-9a-fA-F]{40}`
     */
    function parseAddress(string memory input) internal pure returns (address) {
        return parseAddress(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseAddress-string} that parses a substring of `input` located between position `begin` (included) and
     * `end` (excluded).
     *
     * Requirements:
     * - The substring must be formatted as `(0x)?[0-9a-fA-F]{40}`
     */
    function parseAddress(string memory input, uint256 begin, uint256 end) internal pure returns (address) {
        (bool success, address value) = tryParseAddress(input, begin, end);
        if (!success) revert StringsInvalidAddressFormat();
        return value;
    }

    /**
     * @dev Variant of {parseAddress-string} that returns false if the parsing fails because the input is not a properly
     * formatted address. See {parseAddress-string} requirements.
     */
    function tryParseAddress(string memory input) internal pure returns (bool success, address value) {
        return tryParseAddress(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseAddress-string-uint256-uint256} that returns false if the parsing fails because input is not a properly
     * formatted address. See {parseAddress-string-uint256-uint256} requirements.
     */
    function tryParseAddress(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, address value) {
        if (end > bytes(input).length || begin > end) return (false, address(0));

        bool hasPrefix = (end > begin + 1) && bytes2(_unsafeReadBytesOffset(bytes(input), begin)) == bytes2("0x"); // don't do out-of-bound (possibly unsafe) read if sub-string is empty
        uint256 expectedLength = 40 + hasPrefix.toUint() * 2;

        // check that input is the correct length
        if (end - begin == expectedLength) {
            // length guarantees that this does not overflow, and value is at most type(uint160).max
            (bool s, uint256 v) = _tryParseHexUintUncheckedBounds(input, begin, end);
            return (s, address(uint160(v)));
        } else {
            return (false, address(0));
        }
    }

    function _tryParseChr(bytes1 chr) private pure returns (uint8) {
        uint8 value = uint8(chr);

        // Try to parse `chr`:
        // - Case 1: [0-9]
        // - Case 2: [a-f]
        // - Case 3: [A-F]
        // - otherwise not supported
        unchecked {
            if (value > 47 && value < 58) value -= 48;
            else if (value > 96 && value < 103) value -= 87;
            else if (value > 64 && value < 71) value -= 55;
            else return type(uint8).max;
        }

        return value;
    }

    /**
     * @dev Escape special characters in JSON strings. This can be useful to prevent JSON injection in NFT metadata.
     *
     * WARNING: This function should only be used in double quoted JSON strings. Single quotes are not escaped.
     *
     * NOTE: This function escapes all unicode characters, and not just the ones in ranges defined in section 2.5 of
     * RFC-4627 (U+0000 to U+001F, U+0022 and U+005C). ECMAScript's `JSON.parse` does recover escaped unicode
     * characters that are not in this range, but other tooling may provide different results.
     */
    function escapeJSON(string memory input) internal pure returns (string memory) {
        bytes memory buffer = bytes(input);
        bytes memory output = new bytes(2 * buffer.length); // worst case scenario
        uint256 outputLength = 0;

        for (uint256 i; i < buffer.length; ++i) {
            bytes1 char = bytes1(_unsafeReadBytesOffset(buffer, i));
            if (((SPECIAL_CHARS_LOOKUP & (1 << uint8(char))) != 0)) {
                output[outputLength++] = "\\";
                if (char == 0x08) output[outputLength++] = "b";
                else if (char == 0x09) output[outputLength++] = "t";
                else if (char == 0x0a) output[outputLength++] = "n";
                else if (char == 0x0c) output[outputLength++] = "f";
                else if (char == 0x0d) output[outputLength++] = "r";
                else if (char == 0x5c) output[outputLength++] = "\\";
                else if (char == 0x22) {
                    // solhint-disable-next-line quotes
                    output[outputLength++] = '"';
                }
            } else {
                output[outputLength++] = char;
            }
        }
        // write the actual length and deallocate unused memory
        assembly ("memory-safe") {
            mstore(output, outputLength)
            mstore(0x40, add(output, shl(5, shr(5, add(outputLength, 63)))))
        }

        return string(output);
    }

    /**
     * @dev Reads a bytes32 from a bytes array without bounds checking.
     *
     * NOTE: making this function internal would mean it could be used with memory unsafe offset, and marking the
     * assembly block as such would prevent some optimizations.
     */
    function _unsafeReadBytesOffset(bytes memory buffer, uint256 offset) private pure returns (bytes32 value) {
        // This is not memory safe in the general case, but all calls to this private function are within bounds.
        assembly ("memory-safe") {
            value := mload(add(add(buffer, 0x20), offset))
        }
    }
}


// File @fhenixprotocol/cofhe-contracts/FHE.sol@v0.0.13

// Original license: SPDX_License_Identifier: BSD-3-Clause-Clear
// solhint-disable one-contract-per-file

pragma solidity >=0.8.19 <0.9.0;


type ebool is uint256;
type euint8 is uint256;
type euint16 is uint256;
type euint32 is uint256;
type euint64 is uint256;
type euint128 is uint256;
type euint256 is uint256;
type eaddress is uint256;

// ================================
// \/ \/ \/ \/ \/ \/ \/ \/ \/ \/ \/
// TODO : CHANGE ME AFTER DEPLOYING
// /\ /\ /\ /\ /\ /\ /\ /\ /\ /\ /\
// ================================
//solhint-disable const-name-snakecase
address constant TASK_MANAGER_ADDRESS = 0xeA30c4B8b44078Bbf8a6ef5b9f1eC1626C7848D9;

library Common {
    error InvalidHexCharacter(bytes1 char);
    error SecurityZoneOutOfBounds(int32 value);

    // Default value for temp hash calculation in unary operations
    string private constant DEFAULT_VALUE = "0";

    function convertInt32ToUint256(int32 value) internal pure returns (uint256) {
        if (value < 0) {
            revert SecurityZoneOutOfBounds(value);
        }
        return uint256(uint32(value));
    }

    function isInitialized(uint256 hash) internal pure returns (bool) {
        return hash != 0;
    }

    // Return true if the encrypted integer is initialized and false otherwise.
    function isInitialized(ebool v) internal pure returns (bool) {
        return isInitialized(ebool.unwrap(v));
    }

    // Return true if the encrypted integer is initialized and false otherwise.
    function isInitialized(euint8 v) internal pure returns (bool) {
        return isInitialized(euint8.unwrap(v));
    }

    // Return true if the encrypted integer is initialized and false otherwise.
    function isInitialized(euint16 v) internal pure returns (bool) {
        return isInitialized(euint16.unwrap(v));
    }

    // Return true if the encrypted integer is initialized and false otherwise.
    function isInitialized(euint32 v) internal pure returns (bool) {
        return isInitialized(euint32.unwrap(v));
    }

    // Return true if the encrypted integer is initialized and false otherwise.
    function isInitialized(euint64 v) internal pure returns (bool) {
        return isInitialized(euint64.unwrap(v));
    }

    // Return true if the encrypted integer is initialized and false otherwise.
    function isInitialized(euint128 v) internal pure returns (bool) {
        return isInitialized(euint128.unwrap(v));
    }

    // Return true if the encrypted integer is initialized and false otherwise.
    function isInitialized(euint256 v) internal pure returns (bool) {
        return isInitialized(euint256.unwrap(v));
    }

    function isInitialized(eaddress v) internal pure returns (bool) {
        return isInitialized(eaddress.unwrap(v));
    }

    function createUint256Inputs(uint256 input1) internal pure returns (uint256[] memory) {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = input1;
        return inputs;
    }

    function createUint256Inputs(uint256 input1, uint256 input2) internal pure returns (uint256[] memory) {
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = input1;
        inputs[1] = input2;
        return inputs;
    }

    function createUint256Inputs(uint256 input1, uint256 input2, uint256 input3) internal pure returns (uint256[] memory) {
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = input1;
        inputs[1] = input2;
        inputs[2] = input3;
        return inputs;
    }
}

library Impl {
    function trivialEncrypt(uint256 value, uint8 toType, int32 securityZone) internal returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).createTask(toType, FunctionId.trivialEncrypt, new uint256[](0), Common.createUint256Inputs(value, toType, Common.convertInt32ToUint256(securityZone)));
    }

    function cast(uint256 key, uint8 toType) internal returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).createTask(toType, FunctionId.cast, Common.createUint256Inputs(key), Common.createUint256Inputs(toType));
    }

    function select(uint8 returnType, ebool control, uint256 ifTrue, uint256 ifFalse) internal returns (uint256 result) {
        return ITaskManager(TASK_MANAGER_ADDRESS).createTask(returnType,
            FunctionId.select,
            Common.createUint256Inputs(ebool.unwrap(control), ifTrue, ifFalse),
            new uint256[](0));
    }

    function mathOp(uint8 returnType, uint256 lhs, uint256 rhs, FunctionId functionId) internal returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).createTask(returnType, functionId, Common.createUint256Inputs(lhs, rhs), new uint256[](0));
    }

    function decrypt(uint256 input) internal returns (uint256) {
        ITaskManager(TASK_MANAGER_ADDRESS).createDecryptTask(input, msg.sender);
        return input;
    }

    function getDecryptResult(uint256 input) internal view returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).getDecryptResult(input);
    }

    function getDecryptResultSafe(uint256 input) internal view returns (uint256 result, bool decrypted) {
        return ITaskManager(TASK_MANAGER_ADDRESS).getDecryptResultSafe(input);
    }

    function not(uint8 returnType, uint256 input) internal returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).createTask(returnType, FunctionId.not, Common.createUint256Inputs(input), new uint256[](0));
    }

    function square(uint8 returnType, uint256 input) internal returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).createTask(returnType, FunctionId.square, Common.createUint256Inputs(input), new uint256[](0));
    }

    function verifyInput(EncryptedInput memory input) internal returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).verifyInput(input, msg.sender);
    }

    /// @notice Generates a random value of a given type with the given seed, for the provided securityZone
    /// @dev Calls the desired function
    /// @param uintType the type of the random value to generate
    /// @param seed the seed to use to create a random value from
    /// @param securityZone the security zone to use for the random value
    function random(uint8 uintType, uint64 seed, int32 securityZone) internal returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).createTask(uintType, FunctionId.random, new uint256[](0), Common.createUint256Inputs(seed, Common.convertInt32ToUint256(securityZone)));
    }

    /// @notice Generates a random value of a given type with the given seed
    /// @dev Calls the desired function
    /// @param uintType the type of the random value to generate
    /// @param seed the seed to use to create a random value from
    function random(uint8 uintType, uint32 seed) internal returns (uint256) {
        return random(uintType, seed, 0);
    }

    /// @notice Generates a random value of a given type
    /// @dev Calls the desired function
    /// @param uintType the type of the random value to generate
    function random(uint8 uintType) internal returns (uint256) {
        return random(uintType, 0, 0);
    }

}

library FHE {

    error InvalidEncryptedInput(uint8 got, uint8 expected);
    /// @notice Perform the addition operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted addition
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the addition result
    function add(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.add));
    }

    /// @notice Perform the addition operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted addition
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the addition result
    function add(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.add));
    }

    /// @notice Perform the addition operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted addition
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the addition result
    function add(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.add));
    }

    /// @notice Perform the addition operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted addition
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the addition result
    function add(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.add));
    }

    /// @notice Perform the addition operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted addition
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the addition result
    function add(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.add));
    }

    /// @notice Perform the addition operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted addition
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the addition result
    function add(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.add));
    }

    /// @notice Perform the less than or equal to operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type ebool containing the comparison result
    function lte(euint8 lhs, euint8 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.lte));
    }

    /// @notice Perform the less than or equal to operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type ebool containing the comparison result
    function lte(euint16 lhs, euint16 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.lte));
    }

    /// @notice Perform the less than or equal to operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type ebool containing the comparison result
    function lte(euint32 lhs, euint32 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.lte));
    }

    /// @notice Perform the less than or equal to operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type ebool containing the comparison result
    function lte(euint64 lhs, euint64 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.lte));
    }

    /// @notice Perform the less than or equal to operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type ebool containing the comparison result
    function lte(euint128 lhs, euint128 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.lte));
    }

    /// @notice Perform the less than or equal to operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type ebool containing the comparison result
    function lte(euint256 lhs, euint256 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.lte));
    }

    /// @notice Perform the subtraction operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted subtraction
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the subtraction result
    function sub(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.sub));
    }

    /// @notice Perform the subtraction operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted subtraction
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the subtraction result
    function sub(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.sub));
    }

    /// @notice Perform the subtraction operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted subtraction
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the subtraction result
    function sub(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.sub));
    }

    /// @notice Perform the subtraction operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted subtraction
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the subtraction result
    function sub(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.sub));
    }

    /// @notice Perform the subtraction operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted subtraction
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the subtraction result
    function sub(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.sub));
    }

    /// @notice Perform the subtraction operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted subtraction
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the subtraction result
    function sub(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.sub));
    }

    /// @notice Perform the multiplication operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted multiplication
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the multiplication result
    function mul(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.mul));
    }

    /// @notice Perform the multiplication operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted multiplication
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the multiplication result
    function mul(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.mul));
    }

    /// @notice Perform the multiplication operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted multiplication
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the multiplication result
    function mul(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.mul));
    }

    /// @notice Perform the multiplication operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted multiplication
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the multiplication result
    function mul(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.mul));
    }

    /// @notice Perform the multiplication operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted multiplication
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the multiplication result
    function mul(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.mul));
    }

    /// @notice Perform the multiplication operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted multiplication
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the multiplication result
    function mul(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.mul));
    }

    /// @notice Perform the less than operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type ebool containing the comparison result
    function lt(euint8 lhs, euint8 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.lt));
    }

    /// @notice Perform the less than operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type ebool containing the comparison result
    function lt(euint16 lhs, euint16 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.lt));
    }

    /// @notice Perform the less than operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type ebool containing the comparison result
    function lt(euint32 lhs, euint32 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.lt));
    }

    /// @notice Perform the less than operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type ebool containing the comparison result
    function lt(euint64 lhs, euint64 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.lt));
    }

    /// @notice Perform the less than operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type ebool containing the comparison result
    function lt(euint128 lhs, euint128 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.lt));
    }

    /// @notice Perform the less than operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type ebool containing the comparison result
    function lt(euint256 lhs, euint256 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.lt));
    }

    /// @notice Perform the division operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted division
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the division result
    function div(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.div));
    }

    /// @notice Perform the division operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted division
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the division result
    function div(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.div));
    }

    /// @notice Perform the division operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted division
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the division result
    function div(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.div));
    }

    /// @notice Perform the division operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted division
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the division result
    function div(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.div));
    }

    /// @notice Perform the division operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted division
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the division result
    function div(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.div));
    }

    /// @notice Perform the division operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted division
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the division result
    function div(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.div));
    }

    /// @notice Perform the greater than operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type ebool containing the comparison result
    function gt(euint8 lhs, euint8 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.gt));
    }

    /// @notice Perform the greater than operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type ebool containing the comparison result
    function gt(euint16 lhs, euint16 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.gt));
    }

    /// @notice Perform the greater than operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type ebool containing the comparison result
    function gt(euint32 lhs, euint32 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.gt));
    }

    /// @notice Perform the greater than operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type ebool containing the comparison result
    function gt(euint64 lhs, euint64 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.gt));
    }

    /// @notice Perform the greater than operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type ebool containing the comparison result
    function gt(euint128 lhs, euint128 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.gt));
    }

    /// @notice Perform the greater than operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type ebool containing the comparison result
    function gt(euint256 lhs, euint256 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.gt));
    }

    /// @notice Perform the greater than or equal to operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type ebool containing the comparison result
    function gte(euint8 lhs, euint8 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.gte));
    }

    /// @notice Perform the greater than or equal to operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type ebool containing the comparison result
    function gte(euint16 lhs, euint16 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.gte));
    }

    /// @notice Perform the greater than or equal to operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type ebool containing the comparison result
    function gte(euint32 lhs, euint32 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.gte));
    }

    /// @notice Perform the greater than or equal to operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type ebool containing the comparison result
    function gte(euint64 lhs, euint64 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.gte));
    }

    /// @notice Perform the greater than or equal to operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type ebool containing the comparison result
    function gte(euint128 lhs, euint128 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.gte));
    }

    /// @notice Perform the greater than or equal to operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type ebool containing the comparison result
    function gte(euint256 lhs, euint256 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.gte));
    }

    /// @notice Perform the remainder operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted remainder calculation
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the remainder result
    function rem(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.rem));
    }

    /// @notice Perform the remainder operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted remainder calculation
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the remainder result
    function rem(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.rem));
    }

    /// @notice Perform the remainder operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted remainder calculation
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the remainder result
    function rem(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.rem));
    }

    /// @notice Perform the remainder operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted remainder calculation
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the remainder result
    function rem(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.rem));
    }

    /// @notice Perform the remainder operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted remainder calculation
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the remainder result
    function rem(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.rem));
    }

    /// @notice Perform the remainder operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted remainder calculation
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the remainder result
    function rem(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.rem));
    }

    /// @notice Perform the bitwise AND operation on two parameters of type ebool
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise AND
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return result of type ebool containing the AND result
    function and(ebool lhs, ebool rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEbool(true);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEbool(true);
        }

        return ebool.wrap(Impl.mathOp(Utils.EBOOL_TFHE, ebool.unwrap(lhs), ebool.unwrap(rhs), FunctionId.and));
    }

    /// @notice Perform the bitwise AND operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise AND
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the AND result
    function and(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.and));
    }

    /// @notice Perform the bitwise AND operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise AND
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the AND result
    function and(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.and));
    }

    /// @notice Perform the bitwise AND operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise AND
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the AND result
    function and(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.and));
    }

    /// @notice Perform the bitwise AND operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise AND
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the AND result
    function and(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.and));
    }

    /// @notice Perform the bitwise AND operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise AND
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the AND result
    function and(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.and));
    }

    /// @notice Perform the bitwise AND operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise AND
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the AND result
    function and(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.and));
    }

    /// @notice Perform the bitwise OR operation on two parameters of type ebool
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise OR
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return result of type ebool containing the OR result
    function or(ebool lhs, ebool rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEbool(true);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEbool(true);
        }

        return ebool.wrap(Impl.mathOp(Utils.EBOOL_TFHE, ebool.unwrap(lhs), ebool.unwrap(rhs), FunctionId.or));
    }

    /// @notice Perform the bitwise OR operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise OR
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the OR result
    function or(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.or));
    }

    /// @notice Perform the bitwise OR operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise OR
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the OR result
    function or(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.or));
    }

    /// @notice Perform the bitwise OR operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise OR
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the OR result
    function or(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.or));
    }

    /// @notice Perform the bitwise OR operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise OR
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the OR result
    function or(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.or));
    }

    /// @notice Perform the bitwise OR operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise OR
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the OR result
    function or(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.or));
    }

    /// @notice Perform the bitwise OR operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise OR
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the OR result
    function or(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.or));
    }

    /// @notice Perform the bitwise XOR operation on two parameters of type ebool
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise XOR
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return result of type ebool containing the XOR result
    function xor(ebool lhs, ebool rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEbool(true);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEbool(true);
        }

        return ebool.wrap(Impl.mathOp(Utils.EBOOL_TFHE, ebool.unwrap(lhs), ebool.unwrap(rhs), FunctionId.xor));
    }

    /// @notice Perform the bitwise XOR operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise XOR
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the XOR result
    function xor(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.xor));
    }

    /// @notice Perform the bitwise XOR operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise XOR
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the XOR result
    function xor(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.xor));
    }

    /// @notice Perform the bitwise XOR operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise XOR
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the XOR result
    function xor(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.xor));
    }

    /// @notice Perform the bitwise XOR operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise XOR
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the XOR result
    function xor(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.xor));
    }

    /// @notice Perform the bitwise XOR operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise XOR
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the XOR result
    function xor(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.xor));
    }

    /// @notice Perform the bitwise XOR operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise XOR
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the XOR result
    function xor(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.xor));
    }

    /// @notice Perform the equality operation on two parameters of type ebool
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return result of type ebool containing the equality result
    function eq(ebool lhs, ebool rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEbool(true);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEbool(true);
        }

        return ebool.wrap(Impl.mathOp(Utils.EBOOL_TFHE, ebool.unwrap(lhs), ebool.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the equality operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type ebool containing the equality result
    function eq(euint8 lhs, euint8 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the equality operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type ebool containing the equality result
    function eq(euint16 lhs, euint16 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the equality operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type ebool containing the equality result
    function eq(euint32 lhs, euint32 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the equality operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type ebool containing the equality result
    function eq(euint64 lhs, euint64 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the equality operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type ebool containing the equality result
    function eq(euint128 lhs, euint128 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the equality operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type ebool containing the equality result
    function eq(euint256 lhs, euint256 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the equality operation on two parameters of type eaddress
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type eaddress
    /// @param rhs second input of type eaddress
    /// @return result of type ebool containing the equality result
    function eq(eaddress lhs, eaddress rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEaddress(address(0));
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEaddress(address(0));
        }

        return ebool.wrap(Impl.mathOp(Utils.EADDRESS_TFHE, eaddress.unwrap(lhs), eaddress.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the inequality operation on two parameters of type ebool
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return result of type ebool containing the inequality result
    function ne(ebool lhs, ebool rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEbool(true);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEbool(true);
        }

        return ebool.wrap(Impl.mathOp(Utils.EBOOL_TFHE, ebool.unwrap(lhs), ebool.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the inequality operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type ebool containing the inequality result
    function ne(euint8 lhs, euint8 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the inequality operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type ebool containing the inequality result
    function ne(euint16 lhs, euint16 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the inequality operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type ebool containing the inequality result
    function ne(euint32 lhs, euint32 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the inequality operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type ebool containing the inequality result
    function ne(euint64 lhs, euint64 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the inequality operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type ebool containing the inequality result
    function ne(euint128 lhs, euint128 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the inequality operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type ebool containing the inequality result
    function ne(euint256 lhs, euint256 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the inequality operation on two parameters of type eaddress
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type eaddress
    /// @param rhs second input of type eaddress
    /// @return result of type ebool containing the inequality result
    function ne(eaddress lhs, eaddress rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEaddress(address(0));
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEaddress(address(0));
        }

        return ebool.wrap(Impl.mathOp(Utils.EADDRESS_TFHE, eaddress.unwrap(lhs), eaddress.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the minimum operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted minimum comparison
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the minimum value
    function min(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.min));
    }

    /// @notice Perform the minimum operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted minimum comparison
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the minimum value
    function min(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.min));
    }

    /// @notice Perform the minimum operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted minimum comparison
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the minimum value
    function min(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.min));
    }

    /// @notice Perform the minimum operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted minimum comparison
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the minimum value
    function min(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.min));
    }

    /// @notice Perform the minimum operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted minimum comparison
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the minimum value
    function min(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.min));
    }

    /// @notice Perform the minimum operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted minimum comparison
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the minimum value
    function min(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.min));
    }

    /// @notice Perform the maximum operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted maximum calculation
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the maximum result
    function max(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.max));
    }

    /// @notice Perform the maximum operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted maximum calculation
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the maximum result
    function max(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.max));
    }

    /// @notice Perform the maximum operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted maximum calculation
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the maximum result
    function max(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.max));
    }

    /// @notice Perform the maximum operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted maximum comparison
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the maximum value
    function max(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.max));
    }

    /// @notice Perform the maximum operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted maximum comparison
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the maximum value
    function max(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.max));
    }

    /// @notice Perform the maximum operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted maximum comparison
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the maximum value
    function max(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.max));
    }

    /// @notice Perform the shift left operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted left shift
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the left shift result
    function shl(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.shl));
    }

    /// @notice Perform the shift left operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted left shift
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the left shift result
    function shl(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.shl));
    }

    /// @notice Perform the shift left operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted left shift
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the left shift result
    function shl(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.shl));
    }

    /// @notice Perform the shift left operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted left shift
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the left shift result
    function shl(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.shl));
    }

    /// @notice Perform the shift left operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted left shift
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the left shift result
    function shl(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.shl));
    }

    /// @notice Perform the shift left operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted left shift
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the left shift result
    function shl(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.shl));
    }

    /// @notice Perform the shift right operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted right shift
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the right shift result
    function shr(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.shr));
    }

    /// @notice Perform the shift right operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted right shift
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the right shift result
    function shr(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.shr));
    }

    /// @notice Perform the shift right operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted right shift
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the right shift result
    function shr(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.shr));
    }

    /// @notice Perform the shift right operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted right shift
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the right shift result
    function shr(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.shr));
    }

    /// @notice Perform the shift right operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted right shift
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the right shift result
    function shr(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.shr));
    }

    /// @notice Perform the shift right operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted right shift
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the right shift result
    function shr(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.shr));
    }

    /// @notice Perform the rol operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted left rotation
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the left rotation result
    function rol(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.rol));
    }

    /// @notice Perform the rotate left operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted left rotation
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the left rotation result
    function rol(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.rol));
    }

    /// @notice Perform the rotate left operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted left rotation
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the left rotation result
    function rol(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.rol));
    }

    /// @notice Perform the rotate left operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted left rotation
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the left rotation result
    function rol(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.rol));
    }

    /// @notice Perform the rotate left operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted left rotation
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the left rotation result
    function rol(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.rol));
    }

    /// @notice Perform the rotate left operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted left rotation
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the left rotation result
    function rol(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.rol));
    }

    /// @notice Perform the rotate right operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted right rotation
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the right rotation result
    function ror(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.ror));
    }

    /// @notice Perform the rotate right operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted right rotation
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the right rotation result
    function ror(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.ror));
    }

    /// @notice Perform the rotate right operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted right rotation
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the right rotation result
    function ror(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.ror));
    }

    /// @notice Perform the rotate right operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted right rotation
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the right rotation result
    function ror(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.ror));
    }

    /// @notice Perform the rotate right operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted right rotation
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the right rotation result
    function ror(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.ror));
    }

    /// @notice Perform the rotate right operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted right rotation
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the right rotation result
    function ror(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.ror));
    }

    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(ebool input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }

        ebool.wrap(Impl.decrypt(ebool.unwrap(input1)));
    }
    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(euint8 input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint8(0);
        }

        euint8.wrap(Impl.decrypt(euint8.unwrap(input1)));
    }
    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(euint16 input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint16(0);
        }

        euint16.wrap(Impl.decrypt(euint16.unwrap(input1)));
    }
    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(euint32 input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint32(0);
        }

        euint32.wrap(Impl.decrypt(euint32.unwrap(input1)));
    }
    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(euint64 input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint64(0);
        }

        euint64.wrap(Impl.decrypt(euint64.unwrap(input1)));
    }
    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(euint128 input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint128(0);
        }

        euint128.wrap(Impl.decrypt(euint128.unwrap(input1)));
    }
    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(euint256 input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint256(0);
        }

        euint256.wrap(Impl.decrypt(euint256.unwrap(input1)));
    }
    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(eaddress input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEaddress(address(0));
        }

        Impl.decrypt(eaddress.unwrap(input1));
    }

    /// @notice Gets the decrypted value from a previously decrypted ebool ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The ebool ciphertext to get the decrypted value from
    /// @return The decrypted boolean value
    function getDecryptResult(ebool input1) internal view returns (bool) {
        uint256 result = Impl.getDecryptResult(ebool.unwrap(input1));
        return result != 0;
    }

    /// @notice Gets the decrypted value from a previously decrypted euint8 ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The euint8 ciphertext to get the decrypted value from
    /// @return The decrypted uint8 value
    function getDecryptResult(euint8 input1) internal view returns (uint8) {
        return uint8(Impl.getDecryptResult(euint8.unwrap(input1)));
    }

    /// @notice Gets the decrypted value from a previously decrypted euint16 ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The euint16 ciphertext to get the decrypted value from
    /// @return The decrypted uint16 value
    function getDecryptResult(euint16 input1) internal view returns (uint16) {
        return uint16(Impl.getDecryptResult(euint16.unwrap(input1)));
    }

    /// @notice Gets the decrypted value from a previously decrypted euint32 ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The euint32 ciphertext to get the decrypted value from
    /// @return The decrypted uint32 value
    function getDecryptResult(euint32 input1) internal view returns (uint32) {
        return uint32(Impl.getDecryptResult(euint32.unwrap(input1)));
    }

    /// @notice Gets the decrypted value from a previously decrypted euint64 ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The euint64 ciphertext to get the decrypted value from
    /// @return The decrypted uint64 value
    function getDecryptResult(euint64 input1) internal view returns (uint64) {
        return uint64(Impl.getDecryptResult(euint64.unwrap(input1)));
    }

    /// @notice Gets the decrypted value from a previously decrypted euint128 ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The euint128 ciphertext to get the decrypted value from
    /// @return The decrypted uint128 value
    function getDecryptResult(euint128 input1) internal view returns (uint128) {
        return uint128(Impl.getDecryptResult(euint128.unwrap(input1)));
    }

    /// @notice Gets the decrypted value from a previously decrypted euint256 ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The euint256 ciphertext to get the decrypted value from
    /// @return The decrypted uint256 value
    function getDecryptResult(euint256 input1) internal view returns (uint256) {
        return uint256(Impl.getDecryptResult(euint256.unwrap(input1)));
    }

    /// @notice Gets the decrypted value from a previously decrypted eaddress ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The eaddress ciphertext to get the decrypted value from
    /// @return The decrypted address value
    function getDecryptResult(eaddress input1) internal view returns (address) {
        return address(uint160(Impl.getDecryptResult(eaddress.unwrap(input1))));
    }

    /// @notice Gets the decrypted value from a previously decrypted raw ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The raw ciphertext to get the decrypted value from
    /// @return The decrypted uint256 value
    function getDecryptResult(uint256 input1) internal view returns (uint256) {
        return Impl.getDecryptResult(input1);
    }

    /// @notice Safely gets the decrypted value from an ebool ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The ebool ciphertext to get the decrypted value from
    /// @return result The decrypted boolean value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(ebool input1) internal view returns (bool result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(ebool.unwrap(input1));
        return (_result != 0, _decrypted);
    }

    /// @notice Safely gets the decrypted value from a euint8 ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The euint8 ciphertext to get the decrypted value from
    /// @return result The decrypted uint8 value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(euint8 input1) internal view returns (uint8 result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(euint8.unwrap(input1));
        return (uint8(_result), _decrypted);
    }

    /// @notice Safely gets the decrypted value from a euint16 ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The euint16 ciphertext to get the decrypted value from
    /// @return result The decrypted uint16 value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(euint16 input1) internal view returns (uint16 result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(euint16.unwrap(input1));
        return (uint16(_result), _decrypted);
    }

    /// @notice Safely gets the decrypted value from a euint32 ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The euint32 ciphertext to get the decrypted value from
    /// @return result The decrypted uint32 value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(euint32 input1) internal view returns (uint32 result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(euint32.unwrap(input1));
        return (uint32(_result), _decrypted);
    }

    /// @notice Safely gets the decrypted value from a euint64 ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The euint64 ciphertext to get the decrypted value from
    /// @return result The decrypted uint64 value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(euint64 input1) internal view returns (uint64 result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(euint64.unwrap(input1));
        return (uint64(_result), _decrypted);
    }

    /// @notice Safely gets the decrypted value from a euint128 ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The euint128 ciphertext to get the decrypted value from
    /// @return result The decrypted uint128 value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(euint128 input1) internal view returns (uint128 result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(euint128.unwrap(input1));
        return (uint128(_result), _decrypted);
    }

    /// @notice Safely gets the decrypted value from a euint256 ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The euint256 ciphertext to get the decrypted value from
    /// @return result The decrypted uint256 value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(euint256 input1) internal view returns (uint256 result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(euint256.unwrap(input1));
        return (uint256(_result), _decrypted);
    }

    /// @notice Safely gets the decrypted value from an eaddress ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The eaddress ciphertext to get the decrypted value from
    /// @return result The decrypted address value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(eaddress input1) internal view returns (address result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(eaddress.unwrap(input1));
        return (address(uint160(_result)), _decrypted);
    }

    /// @notice Safely gets the decrypted value from a raw ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The raw ciphertext to get the decrypted value from
    /// @return result The decrypted uint256 value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(uint256 input1) internal view returns (uint256 result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(input1);
        return (_result, _decrypted);
    }

    /// @notice Performs a multiplexer operation between two ebool values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type ebool
    /// @param input3 Second choice of type ebool
    /// @return result of type ebool containing the selected value
    function select(ebool input1, ebool input2, ebool input3) internal returns (ebool) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEbool(false);
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEbool(false);
        }

        return ebool.wrap(Impl.select(Utils.EBOOL_TFHE, input1, ebool.unwrap(input2), ebool.unwrap(input3)));
    }

    /// @notice Performs a multiplexer operation between two euint8 values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type euint8
    /// @param input3 Second choice of type euint8
    /// @return result of type euint8 containing the selected value
    function select(ebool input1, euint8 input2, euint8 input3) internal returns (euint8) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEuint8(0);
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEuint8(0);
        }

        return euint8.wrap(Impl.select(Utils.EUINT8_TFHE, input1, euint8.unwrap(input2), euint8.unwrap(input3)));
    }

    /// @notice Performs a multiplexer operation between two euint16 values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type euint16
    /// @param input3 Second choice of type euint16
    /// @return result of type euint16 containing the selected value
    function select(ebool input1, euint16 input2, euint16 input3) internal returns (euint16) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEuint16(0);
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEuint16(0);
        }

        return euint16.wrap(Impl.select(Utils.EUINT16_TFHE, input1, euint16.unwrap(input2), euint16.unwrap(input3)));
    }

    /// @notice Performs a multiplexer operation between two euint32 values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type euint32
    /// @param input3 Second choice of type euint32
    /// @return result of type euint32 containing the selected value
    function select(ebool input1, euint32 input2, euint32 input3) internal returns (euint32) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEuint32(0);
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEuint32(0);
        }

        return euint32.wrap(Impl.select(Utils.EUINT32_TFHE, input1, euint32.unwrap(input2), euint32.unwrap(input3)));
    }

    /// @notice Performs a multiplexer operation between two euint64 values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type euint64
    /// @param input3 Second choice of type euint64
    /// @return result of type euint64 containing the selected value
    function select(ebool input1, euint64 input2, euint64 input3) internal returns (euint64) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEuint64(0);
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEuint64(0);
        }

        return euint64.wrap(Impl.select(Utils.EUINT64_TFHE, input1, euint64.unwrap(input2), euint64.unwrap(input3)));
    }

    /// @notice Performs a multiplexer operation between two euint128 values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type euint128
    /// @param input3 Second choice of type euint128
    /// @return result of type euint128 containing the selected value
    function select(ebool input1, euint128 input2, euint128 input3) internal returns (euint128) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEuint128(0);
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEuint128(0);
        }

        return euint128.wrap(Impl.select(Utils.EUINT128_TFHE, input1, euint128.unwrap(input2), euint128.unwrap(input3)));
    }

    /// @notice Performs a multiplexer operation between two euint256 values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type euint256
    /// @param input3 Second choice of type euint256
    /// @return result of type euint256 containing the selected value
    function select(ebool input1, euint256 input2, euint256 input3) internal returns (euint256) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEuint256(0);
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEuint256(0);
        }

        return euint256.wrap(Impl.select(Utils.EUINT256_TFHE, input1, euint256.unwrap(input2), euint256.unwrap(input3)));
    }

    /// @notice Performs a multiplexer operation between two eaddress values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type eaddress
    /// @param input3 Second choice of type eaddress
    /// @return result of type eaddress containing the selected value
    function select(ebool input1, eaddress input2, eaddress input3) internal returns (eaddress) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEaddress(address(0));
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEaddress(address(0));
        }

        return eaddress.wrap(Impl.select(Utils.EADDRESS_TFHE, input1, eaddress.unwrap(input2), eaddress.unwrap(input3)));
    }

    /// @notice Performs the not operation on a ciphertext
    /// @dev Verifies that the input value matches a valid ciphertext.
    /// @param input1 the input ciphertext
    function not(ebool input1) internal returns (ebool) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }

        return ebool.wrap(Impl.not(Utils.EBOOL_TFHE, ebool.unwrap(input1)));
    }

    /// @notice Performs the not operation on a ciphertext
    /// @dev Verifies that the input value matches a valid ciphertext.
    /// @param input1 the input ciphertext
    function not(euint8 input1) internal returns (euint8) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint8(0);
        }

        return euint8.wrap(Impl.not(Utils.EUINT8_TFHE, euint8.unwrap(input1)));
    }
    /// @notice Performs the not operation on a ciphertext
    /// @dev Verifies that the input value matches a valid ciphertext.
    /// @param input1 the input ciphertext
    function not(euint16 input1) internal returns (euint16) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint16(0);
        }

        return euint16.wrap(Impl.not(Utils.EUINT16_TFHE, euint16.unwrap(input1)));
    }
    /// @notice Performs the not operation on a ciphertext
    /// @dev Verifies that the input value matches a valid ciphertext.
    /// @param input1 the input ciphertext
    function not(euint32 input1) internal returns (euint32) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint32(0);
        }

        return euint32.wrap(Impl.not(Utils.EUINT32_TFHE, euint32.unwrap(input1)));
    }

    /// @notice Performs the bitwise NOT operation on an encrypted 64-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      The operation inverts all bits of the input value.
    /// @param input1 The input ciphertext to negate
    /// @return An euint64 containing the bitwise NOT of the input
    function not(euint64 input1) internal returns (euint64) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint64(0);
        }

        return euint64.wrap(Impl.not(Utils.EUINT64_TFHE, euint64.unwrap(input1)));
    }

    /// @notice Performs the bitwise NOT operation on an encrypted 128-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      The operation inverts all bits of the input value.
    /// @param input1 The input ciphertext to negate
    /// @return An euint128 containing the bitwise NOT of the input
    function not(euint128 input1) internal returns (euint128) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint128(0);
        }

        return euint128.wrap(Impl.not(Utils.EUINT128_TFHE, euint128.unwrap(input1)));
    }

    /// @notice Performs the bitwise NOT operation on an encrypted 256-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      The operation inverts all bits of the input value.
    /// @param input1 The input ciphertext to negate
    /// @return An euint256 containing the bitwise NOT of the input
    function not(euint256 input1) internal returns (euint256) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint256(0);
        }

        return euint256.wrap(Impl.not(Utils.EUINT256_TFHE, euint256.unwrap(input1)));
    }

    /// @notice Performs the square operation on an encrypted 8-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      Note: The result may overflow if input * input exceeds 8 bits.
    /// @param input1 The input ciphertext to square
    /// @return An euint8 containing the square of the input
    function square(euint8 input1) internal returns (euint8) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint8(0);
        }

        return euint8.wrap(Impl.square(Utils.EUINT8_TFHE, euint8.unwrap(input1)));
    }

    /// @notice Performs the square operation on an encrypted 16-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      Note: The result may overflow if input * input exceeds 16 bits.
    /// @param input1 The input ciphertext to square
    /// @return An euint16 containing the square of the input
    function square(euint16 input1) internal returns (euint16) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint16(0);
        }

        return euint16.wrap(Impl.square(Utils.EUINT16_TFHE, euint16.unwrap(input1)));
    }

    /// @notice Performs the square operation on an encrypted 32-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      Note: The result may overflow if input * input exceeds 32 bits.
    /// @param input1 The input ciphertext to square
    /// @return An euint32 containing the square of the input
    function square(euint32 input1) internal returns (euint32) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint32(0);
        }

        return euint32.wrap(Impl.square(Utils.EUINT32_TFHE, euint32.unwrap(input1)));
    }

    /// @notice Performs the square operation on an encrypted 64-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      Note: The result may overflow if input * input exceeds 64 bits.
    /// @param input1 The input ciphertext to square
    /// @return An euint64 containing the square of the input
    function square(euint64 input1) internal returns (euint64) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint64(0);
        }

        return euint64.wrap(Impl.square(Utils.EUINT64_TFHE, euint64.unwrap(input1)));
    }

    /// @notice Performs the square operation on an encrypted 128-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      Note: The result may overflow if input * input exceeds 128 bits.
    /// @param input1 The input ciphertext to square
    /// @return An euint128 containing the square of the input
    function square(euint128 input1) internal returns (euint128) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint128(0);
        }

        return euint128.wrap(Impl.square(Utils.EUINT128_TFHE, euint128.unwrap(input1)));
    }

    /// @notice Performs the square operation on an encrypted 256-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      Note: The result may overflow if input * input exceeds 256 bits.
    /// @param input1 The input ciphertext to square
    /// @return An euint256 containing the square of the input
    function square(euint256 input1) internal returns (euint256) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint256(0);
        }

        return euint256.wrap(Impl.square(Utils.EUINT256_TFHE, euint256.unwrap(input1)));
    }
    /// @notice Generates a random value of a euint8 type for provided securityZone
    /// @dev Generates a cryptographically secure random 8-bit unsigned integer in encrypted form.
    ///      The generated value is fully encrypted and cannot be predicted by any party.
    /// @param securityZone The security zone identifier to use for random value generation.
    /// @return A randomly generated encrypted 8-bit unsigned integer (euint8)
    function randomEuint8(int32 securityZone) internal returns (euint8) {
        return euint8.wrap(Impl.random(Utils.EUINT8_TFHE, 0, securityZone));
    }
    /// @notice Generates a random value of a euint8 type
    /// @dev Generates a cryptographically secure random 8-bit unsigned integer in encrypted form
    ///      using the default security zone (0). The generated value is fully encrypted and
    ///      cannot be predicted by any party.
    /// @return A randomly generated encrypted 8-bit unsigned integer (euint8)
    function randomEuint8() internal returns (euint8) {
        return randomEuint8(0);
    }
    /// @notice Generates a random value of a euint16 type for provided securityZone
    /// @dev Generates a cryptographically secure random 16-bit unsigned integer in encrypted form.
    ///      The generated value is fully encrypted and cannot be predicted by any party.
    /// @param securityZone The security zone identifier to use for random value generation.
    /// @return A randomly generated encrypted 16-bit unsigned integer (euint16)
    function randomEuint16(int32 securityZone) internal returns (euint16) {
        return euint16.wrap(Impl.random(Utils.EUINT16_TFHE, 0, securityZone));
    }
    /// @notice Generates a random value of a euint16 type
    /// @dev Generates a cryptographically secure random 16-bit unsigned integer in encrypted form
    ///      using the default security zone (0). The generated value is fully encrypted and
    ///      cannot be predicted by any party.
    /// @return A randomly generated encrypted 16-bit unsigned integer (euint16)
    function randomEuint16() internal returns (euint16) {
        return randomEuint16(0);
    }
    /// @notice Generates a random value of a euint32 type for provided securityZone
    /// @dev Generates a cryptographically secure random 32-bit unsigned integer in encrypted form.
    ///      The generated value is fully encrypted and cannot be predicted by any party.
    /// @param securityZone The security zone identifier to use for random value generation.
    /// @return A randomly generated encrypted 32-bit unsigned integer (euint32)
    function randomEuint32(int32 securityZone) internal returns (euint32) {
        return euint32.wrap(Impl.random(Utils.EUINT32_TFHE, 0, securityZone));
    }
    /// @notice Generates a random value of a euint32 type
    /// @dev Generates a cryptographically secure random 32-bit unsigned integer in encrypted form
    ///      using the default security zone (0). The generated value is fully encrypted and
    ///      cannot be predicted by any party.
    /// @return A randomly generated encrypted 32-bit unsigned integer (euint32)
    function randomEuint32() internal returns (euint32) {
        return randomEuint32(0);
    }
    /// @notice Generates a random value of a euint64 type for provided securityZone
    /// @dev Generates a cryptographically secure random 64-bit unsigned integer in encrypted form.
    ///      The generated value is fully encrypted and cannot be predicted by any party.
    /// @param securityZone The security zone identifier to use for random value generation.
    /// @return A randomly generated encrypted 64-bit unsigned integer (euint64)
    function randomEuint64(int32 securityZone) internal returns (euint64) {
        return euint64.wrap(Impl.random(Utils.EUINT64_TFHE, 0, securityZone));
    }
    /// @notice Generates a random value of a euint64 type
    /// @dev Generates a cryptographically secure random 64-bit unsigned integer in encrypted form
    ///      using the default security zone (0). The generated value is fully encrypted and
    ///      cannot be predicted by any party.
    /// @return A randomly generated encrypted 64-bit unsigned integer (euint64)
    function randomEuint64() internal returns (euint64) {
        return randomEuint64(0);
    }
    /// @notice Generates a random value of a euint128 type for provided securityZone
    /// @dev Generates a cryptographically secure random 128-bit unsigned integer in encrypted form.
    ///      The generated value is fully encrypted and cannot be predicted by any party.
    /// @param securityZone The security zone identifier to use for random value generation.
    /// @return A randomly generated encrypted 128-bit unsigned integer (euint128)
    function randomEuint128(int32 securityZone) internal returns (euint128) {
        return euint128.wrap(Impl.random(Utils.EUINT128_TFHE, 0, securityZone));
    }
    /// @notice Generates a random value of a euint128 type
    /// @dev Generates a cryptographically secure random 128-bit unsigned integer in encrypted form
    ///      using the default security zone (0). The generated value is fully encrypted and
    ///      cannot be predicted by any party.
    /// @return A randomly generated encrypted 128-bit unsigned integer (euint128)
    function randomEuint128() internal returns (euint128) {
        return randomEuint128(0);
    }
    /// @notice Generates a random value of a euint256 type for provided securityZone
    /// @dev Generates a cryptographically secure random 256-bit unsigned integer in encrypted form.
    ///      The generated value is fully encrypted and cannot be predicted by any party.
    /// @param securityZone The security zone identifier to use for random value generation.
    /// @return A randomly generated encrypted 256-bit unsigned integer (euint256)
    function randomEuint256(int32 securityZone) internal returns (euint256) {
        return euint256.wrap(Impl.random(Utils.EUINT256_TFHE, 0, securityZone));
    }
    /// @notice Generates a random value of a euint256 type
    /// @dev Generates a cryptographically secure random 256-bit unsigned integer in encrypted form
    ///      using the default security zone (0). The generated value is fully encrypted and
    ///      cannot be predicted by any party.
    /// @return A randomly generated encrypted 256-bit unsigned integer (euint256)
    function randomEuint256() internal returns (euint256) {
        return randomEuint256(0);
    }

    /// @notice Verifies and converts an inEbool input to an ebool encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An ebool containing the verified encrypted value
    function asEbool(InEbool memory value) internal returns (ebool) {
        uint8 expectedUtype = Utils.EBOOL_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }

        return ebool.wrap(Impl.verifyInput(Utils.inputFromEbool(value)));
    }

    /// @notice Verifies and converts an InEuint8 input to an euint8 encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An euint8 containing the verified encrypted value
    function asEuint8(InEuint8 memory value) internal returns (euint8) {
        uint8 expectedUtype = Utils.EUINT8_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }


        return euint8.wrap(Impl.verifyInput(Utils.inputFromEuint8(value)));
    }

    /// @notice Verifies and converts an InEuint16 input to an euint16 encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An euint16 containing the verified encrypted value
    function asEuint16(InEuint16 memory value) internal returns (euint16) {
        uint8 expectedUtype = Utils.EUINT16_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }


        return euint16.wrap(Impl.verifyInput(Utils.inputFromEuint16(value)));
    }

    /// @notice Verifies and converts an InEuint32 input to an euint32 encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An euint32 containing the verified encrypted value
    function asEuint32(InEuint32 memory value) internal returns (euint32) {
        uint8 expectedUtype = Utils.EUINT32_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }


        return euint32.wrap(Impl.verifyInput(Utils.inputFromEuint32(value)));
    }

    /// @notice Verifies and converts an InEuint64 input to an euint64 encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An euint64 containing the verified encrypted value
    function asEuint64(InEuint64 memory value) internal returns (euint64) {
        uint8 expectedUtype = Utils.EUINT64_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }


        return euint64.wrap(Impl.verifyInput(Utils.inputFromEuint64(value)));
    }

    /// @notice Verifies and converts an InEuint128 input to an euint128 encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An euint128 containing the verified encrypted value
    function asEuint128(InEuint128 memory value) internal returns (euint128) {
        uint8 expectedUtype = Utils.EUINT128_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }


        return euint128.wrap(Impl.verifyInput(Utils.inputFromEuint128(value)));
    }

    /// @notice Verifies and converts an InEuint256 input to an euint256 encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An euint256 containing the verified encrypted value
    function asEuint256(InEuint256 memory value) internal returns (euint256) {
        uint8 expectedUtype = Utils.EUINT256_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }


        return euint256.wrap(Impl.verifyInput(Utils.inputFromEuint256(value)));
    }

    /// @notice Verifies and converts an InEaddress input to an eaddress encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An eaddress containing the verified encrypted value
    function asEaddress(InEaddress memory value) internal returns (eaddress) {
        uint8 expectedUtype = Utils.EADDRESS_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }


        return eaddress.wrap(Impl.verifyInput(Utils.inputFromEaddress(value)));
    }

    // ********** TYPE CASTING ************* //
    /// @notice Converts a ebool to an euint8
    function asEuint8(ebool value) internal returns (euint8) {
        return euint8.wrap(Impl.cast(ebool.unwrap(value), Utils.EUINT8_TFHE));
    }
    /// @notice Converts a ebool to an euint16
    function asEuint16(ebool value) internal returns (euint16) {
        return euint16.wrap(Impl.cast(ebool.unwrap(value), Utils.EUINT16_TFHE));
    }
    /// @notice Converts a ebool to an euint32
    function asEuint32(ebool value) internal returns (euint32) {
        return euint32.wrap(Impl.cast(ebool.unwrap(value), Utils.EUINT32_TFHE));
    }
    /// @notice Converts a ebool to an euint64
    function asEuint64(ebool value) internal returns (euint64) {
        return euint64.wrap(Impl.cast(ebool.unwrap(value), Utils.EUINT64_TFHE));
    }
    /// @notice Converts a ebool to an euint128
    function asEuint128(ebool value) internal returns (euint128) {
        return euint128.wrap(Impl.cast(ebool.unwrap(value), Utils.EUINT128_TFHE));
    }
    /// @notice Converts a ebool to an euint256
    function asEuint256(ebool value) internal returns (euint256) {
        return euint256.wrap(Impl.cast(ebool.unwrap(value), Utils.EUINT256_TFHE));
    }

    /// @notice Converts a euint8 to an ebool
    function asEbool(euint8 value) internal returns (ebool) {
        return ne(value, asEuint8(0));
    }
    /// @notice Converts a euint8 to an euint16
    function asEuint16(euint8 value) internal returns (euint16) {
        return euint16.wrap(Impl.cast(euint8.unwrap(value), Utils.EUINT16_TFHE));
    }
    /// @notice Converts a euint8 to an euint32
    function asEuint32(euint8 value) internal returns (euint32) {
        return euint32.wrap(Impl.cast(euint8.unwrap(value), Utils.EUINT32_TFHE));
    }
    /// @notice Converts a euint8 to an euint64
    function asEuint64(euint8 value) internal returns (euint64) {
        return euint64.wrap(Impl.cast(euint8.unwrap(value), Utils.EUINT64_TFHE));
    }
    /// @notice Converts a euint8 to an euint128
    function asEuint128(euint8 value) internal returns (euint128) {
        return euint128.wrap(Impl.cast(euint8.unwrap(value), Utils.EUINT128_TFHE));
    }
    /// @notice Converts a euint8 to an euint256
    function asEuint256(euint8 value) internal returns (euint256) {
        return euint256.wrap(Impl.cast(euint8.unwrap(value), Utils.EUINT256_TFHE));
    }

    /// @notice Converts a euint16 to an ebool
    function asEbool(euint16 value) internal returns (ebool) {
        return ne(value, asEuint16(0));
    }
    /// @notice Converts a euint16 to an euint8
    function asEuint8(euint16 value) internal returns (euint8) {
        return euint8.wrap(Impl.cast(euint16.unwrap(value), Utils.EUINT8_TFHE));
    }
    /// @notice Converts a euint16 to an euint32
    function asEuint32(euint16 value) internal returns (euint32) {
        return euint32.wrap(Impl.cast(euint16.unwrap(value), Utils.EUINT32_TFHE));
    }
    /// @notice Converts a euint16 to an euint64
    function asEuint64(euint16 value) internal returns (euint64) {
        return euint64.wrap(Impl.cast(euint16.unwrap(value), Utils.EUINT64_TFHE));
    }
    /// @notice Converts a euint16 to an euint128
    function asEuint128(euint16 value) internal returns (euint128) {
        return euint128.wrap(Impl.cast(euint16.unwrap(value), Utils.EUINT128_TFHE));
    }
    /// @notice Converts a euint16 to an euint256
    function asEuint256(euint16 value) internal returns (euint256) {
        return euint256.wrap(Impl.cast(euint16.unwrap(value), Utils.EUINT256_TFHE));
    }

    /// @notice Converts a euint32 to an ebool
    function asEbool(euint32 value) internal returns (ebool) {
        return ne(value, asEuint32(0));
    }
    /// @notice Converts a euint32 to an euint8
    function asEuint8(euint32 value) internal returns (euint8) {
        return euint8.wrap(Impl.cast(euint32.unwrap(value), Utils.EUINT8_TFHE));
    }
    /// @notice Converts a euint32 to an euint16
    function asEuint16(euint32 value) internal returns (euint16) {
        return euint16.wrap(Impl.cast(euint32.unwrap(value), Utils.EUINT16_TFHE));
    }
    /// @notice Converts a euint32 to an euint64
    function asEuint64(euint32 value) internal returns (euint64) {
        return euint64.wrap(Impl.cast(euint32.unwrap(value), Utils.EUINT64_TFHE));
    }
    /// @notice Converts a euint32 to an euint128
    function asEuint128(euint32 value) internal returns (euint128) {
        return euint128.wrap(Impl.cast(euint32.unwrap(value), Utils.EUINT128_TFHE));
    }
    /// @notice Converts a euint32 to an euint256
    function asEuint256(euint32 value) internal returns (euint256) {
        return euint256.wrap(Impl.cast(euint32.unwrap(value), Utils.EUINT256_TFHE));
    }

    /// @notice Converts a euint64 to an ebool
    function asEbool(euint64 value) internal returns (ebool) {
        return ne(value, asEuint64(0));
    }
    /// @notice Converts a euint64 to an euint8
    function asEuint8(euint64 value) internal returns (euint8) {
        return euint8.wrap(Impl.cast(euint64.unwrap(value), Utils.EUINT8_TFHE));
    }
    /// @notice Converts a euint64 to an euint16
    function asEuint16(euint64 value) internal returns (euint16) {
        return euint16.wrap(Impl.cast(euint64.unwrap(value), Utils.EUINT16_TFHE));
    }
    /// @notice Converts a euint64 to an euint32
    function asEuint32(euint64 value) internal returns (euint32) {
        return euint32.wrap(Impl.cast(euint64.unwrap(value), Utils.EUINT32_TFHE));
    }
    /// @notice Converts a euint64 to an euint128
    function asEuint128(euint64 value) internal returns (euint128) {
        return euint128.wrap(Impl.cast(euint64.unwrap(value), Utils.EUINT128_TFHE));
    }
    /// @notice Converts a euint64 to an euint256
    function asEuint256(euint64 value) internal returns (euint256) {
        return euint256.wrap(Impl.cast(euint64.unwrap(value), Utils.EUINT256_TFHE));
    }

    /// @notice Converts a euint128 to an ebool
    function asEbool(euint128 value) internal returns (ebool) {
        return ne(value, asEuint128(0));
    }
    /// @notice Converts a euint128 to an euint8
    function asEuint8(euint128 value) internal returns (euint8) {
        return euint8.wrap(Impl.cast(euint128.unwrap(value), Utils.EUINT8_TFHE));
    }
    /// @notice Converts a euint128 to an euint16
    function asEuint16(euint128 value) internal returns (euint16) {
        return euint16.wrap(Impl.cast(euint128.unwrap(value), Utils.EUINT16_TFHE));
    }
    /// @notice Converts a euint128 to an euint32
    function asEuint32(euint128 value) internal returns (euint32) {
        return euint32.wrap(Impl.cast(euint128.unwrap(value), Utils.EUINT32_TFHE));
    }
    /// @notice Converts a euint128 to an euint64
    function asEuint64(euint128 value) internal returns (euint64) {
        return euint64.wrap(Impl.cast(euint128.unwrap(value), Utils.EUINT64_TFHE));
    }
    /// @notice Converts a euint128 to an euint256
    function asEuint256(euint128 value) internal returns (euint256) {
        return euint256.wrap(Impl.cast(euint128.unwrap(value), Utils.EUINT256_TFHE));
    }

    /// @notice Converts a euint256 to an ebool
    function asEbool(euint256 value) internal returns (ebool) {
        return ne(value, asEuint256(0));
    }
    /// @notice Converts a euint256 to an euint8
    function asEuint8(euint256 value) internal returns (euint8) {
        return euint8.wrap(Impl.cast(euint256.unwrap(value), Utils.EUINT8_TFHE));
    }
    /// @notice Converts a euint256 to an euint16
    function asEuint16(euint256 value) internal returns (euint16) {
        return euint16.wrap(Impl.cast(euint256.unwrap(value), Utils.EUINT16_TFHE));
    }
    /// @notice Converts a euint256 to an euint32
    function asEuint32(euint256 value) internal returns (euint32) {
        return euint32.wrap(Impl.cast(euint256.unwrap(value), Utils.EUINT32_TFHE));
    }
    /// @notice Converts a euint256 to an euint64
    function asEuint64(euint256 value) internal returns (euint64) {
        return euint64.wrap(Impl.cast(euint256.unwrap(value), Utils.EUINT64_TFHE));
    }
    /// @notice Converts a euint256 to an euint128
    function asEuint128(euint256 value) internal returns (euint128) {
        return euint128.wrap(Impl.cast(euint256.unwrap(value), Utils.EUINT128_TFHE));
    }
    /// @notice Converts a euint256 to an eaddress
    function asEaddress(euint256 value) internal returns (eaddress) {
        return eaddress.wrap(Impl.cast(euint256.unwrap(value), Utils.EADDRESS_TFHE));
    }

    /// @notice Converts a eaddress to an ebool
    function asEbool(eaddress value) internal returns (ebool) {
        return ne(value, asEaddress(address(0)));
    }
    /// @notice Converts a eaddress to an euint8
    function asEuint8(eaddress value) internal returns (euint8) {
        return euint8.wrap(Impl.cast(eaddress.unwrap(value), Utils.EUINT8_TFHE));
    }
    /// @notice Converts a eaddress to an euint16
    function asEuint16(eaddress value) internal returns (euint16) {
        return euint16.wrap(Impl.cast(eaddress.unwrap(value), Utils.EUINT16_TFHE));
    }
    /// @notice Converts a eaddress to an euint32
    function asEuint32(eaddress value) internal returns (euint32) {
        return euint32.wrap(Impl.cast(eaddress.unwrap(value), Utils.EUINT32_TFHE));
    }
    /// @notice Converts a eaddress to an euint64
    function asEuint64(eaddress value) internal returns (euint64) {
        return euint64.wrap(Impl.cast(eaddress.unwrap(value), Utils.EUINT64_TFHE));
    }
    /// @notice Converts a eaddress to an euint128
    function asEuint128(eaddress value) internal returns (euint128) {
        return euint128.wrap(Impl.cast(eaddress.unwrap(value), Utils.EUINT128_TFHE));
    }
    /// @notice Converts a eaddress to an euint256
    function asEuint256(eaddress value) internal returns (euint256) {
        return euint256.wrap(Impl.cast(eaddress.unwrap(value), Utils.EUINT256_TFHE));
    }
    /// @notice Converts a plaintext boolean value to a ciphertext ebool
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    /// @return A ciphertext representation of the input
    function asEbool(bool value) internal returns (ebool) {
        return asEbool(value, 0);
    }
    /// @notice Converts a plaintext boolean value to a ciphertext ebool, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    /// @return A ciphertext representation of the input
    function asEbool(bool value, int32 securityZone) internal returns (ebool) {
        uint256 sVal = 0;
        if (value) {
            sVal = 1;
        }
        uint256 ct = Impl.trivialEncrypt(sVal, Utils.EBOOL_TFHE, securityZone);
        return ebool.wrap(ct);
    }
    /// @notice Converts a uint256 to an euint8
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint8(uint256 value) internal returns (euint8) {
        return asEuint8(value, 0);
    }
    /// @notice Converts a uint256 to an euint8, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint8(uint256 value, int32 securityZone) internal returns (euint8) {
        uint256 ct = Impl.trivialEncrypt(value, Utils.EUINT8_TFHE, securityZone);
        return euint8.wrap(ct);
    }
    /// @notice Converts a uint256 to an euint16
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint16(uint256 value) internal returns (euint16) {
        return asEuint16(value, 0);
    }
    /// @notice Converts a uint256 to an euint16, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint16(uint256 value, int32 securityZone) internal returns (euint16) {
        uint256 ct = Impl.trivialEncrypt(value, Utils.EUINT16_TFHE, securityZone);
        return euint16.wrap(ct);
    }
    /// @notice Converts a uint256 to an euint32
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint32(uint256 value) internal returns (euint32) {
        return asEuint32(value, 0);
    }
    /// @notice Converts a uint256 to an euint32, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint32(uint256 value, int32 securityZone) internal returns (euint32) {
        uint256 ct = Impl.trivialEncrypt(value, Utils.EUINT32_TFHE, securityZone);
        return euint32.wrap(ct);
    }
    /// @notice Converts a uint256 to an euint64
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint64(uint256 value) internal returns (euint64) {
        return asEuint64(value, 0);
    }
    /// @notice Converts a uint256 to an euint64, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint64(uint256 value, int32 securityZone) internal returns (euint64) {
        uint256 ct = Impl.trivialEncrypt(value, Utils.EUINT64_TFHE, securityZone);
        return euint64.wrap(ct);
    }
    /// @notice Converts a uint256 to an euint128
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint128(uint256 value) internal returns (euint128) {
        return asEuint128(value, 0);
    }
    /// @notice Converts a uint256 to an euint128, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint128(uint256 value, int32 securityZone) internal returns (euint128) {
        uint256 ct = Impl.trivialEncrypt(value, Utils.EUINT128_TFHE, securityZone);
        return euint128.wrap(ct);
    }
    /// @notice Converts a uint256 to an euint256
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint256(uint256 value) internal returns (euint256) {
        return asEuint256(value, 0);
    }
    /// @notice Converts a uint256 to an euint256, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint256(uint256 value, int32 securityZone) internal returns (euint256) {
        uint256 ct = Impl.trivialEncrypt(value, Utils.EUINT256_TFHE, securityZone);
        return euint256.wrap(ct);
    }
    /// @notice Converts a address to an eaddress
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    /// Allows for a better user experience when working with eaddresses
    function asEaddress(address value) internal returns (eaddress) {
        return asEaddress(value, 0);
    }
    /// @notice Converts a address to an eaddress, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    /// Allows for a better user experience when working with eaddresses
    function asEaddress(address value, int32 securityZone) internal returns (eaddress) {
        uint256 ct = Impl.trivialEncrypt(uint256(uint160(value)), Utils.EADDRESS_TFHE, securityZone);
        return eaddress.wrap(ct);
    }

    /// @notice Grants permission to an account to operate on the encrypted boolean value
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted boolean value to grant access to
    /// @param account The address being granted permission
    function allow(ebool ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(ebool.unwrap(ctHash), account);
    }

    /// @notice Grants permission to an account to operate on the encrypted 8-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted uint8 value to grant access to
    /// @param account The address being granted permission
    function allow(euint8 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint8.unwrap(ctHash), account);
    }

    /// @notice Grants permission to an account to operate on the encrypted 16-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted uint16 value to grant access to
    /// @param account The address being granted permission
    function allow(euint16 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint16.unwrap(ctHash), account);
    }

    /// @notice Grants permission to an account to operate on the encrypted 32-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted uint32 value to grant access to
    /// @param account The address being granted permission
    function allow(euint32 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint32.unwrap(ctHash), account);
    }

    /// @notice Grants permission to an account to operate on the encrypted 64-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted uint64 value to grant access to
    /// @param account The address being granted permission
    function allow(euint64 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint64.unwrap(ctHash), account);
    }

    /// @notice Grants permission to an account to operate on the encrypted 128-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted uint128 value to grant access to
    /// @param account The address being granted permission
    function allow(euint128 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint128.unwrap(ctHash), account);
    }

    /// @notice Grants permission to an account to operate on the encrypted 256-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted uint256 value to grant access to
    /// @param account The address being granted permission
    function allow(euint256 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint256.unwrap(ctHash), account);
    }

    /// @notice Grants permission to an account to operate on the encrypted address
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted address value to grant access to
    /// @param account The address being granted permission
    function allow(eaddress ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(eaddress.unwrap(ctHash), account);
    }

    /// @notice Grants global permission to operate on the encrypted boolean value
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted boolean value to grant global access to
    function allowGlobal(ebool ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(ebool.unwrap(ctHash));
    }

    /// @notice Grants global permission to operate on the encrypted 8-bit unsigned integer
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted uint8 value to grant global access to
    function allowGlobal(euint8 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(euint8.unwrap(ctHash));
    }

    /// @notice Grants global permission to operate on the encrypted 16-bit unsigned integer
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted uint16 value to grant global access to
    function allowGlobal(euint16 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(euint16.unwrap(ctHash));
    }

    /// @notice Grants global permission to operate on the encrypted 32-bit unsigned integer
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted uint32 value to grant global access to
    function allowGlobal(euint32 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(euint32.unwrap(ctHash));
    }

    /// @notice Grants global permission to operate on the encrypted 64-bit unsigned integer
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted uint64 value to grant global access to
    function allowGlobal(euint64 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(euint64.unwrap(ctHash));
    }

    /// @notice Grants global permission to operate on the encrypted 128-bit unsigned integer
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted uint128 value to grant global access to
    function allowGlobal(euint128 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(euint128.unwrap(ctHash));
    }

    /// @notice Grants global permission to operate on the encrypted 256-bit unsigned integer
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted uint256 value to grant global access to
    function allowGlobal(euint256 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(euint256.unwrap(ctHash));
    }

    /// @notice Grants global permission to operate on the encrypted address
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted address value to grant global access to
    function allowGlobal(eaddress ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(eaddress.unwrap(ctHash));
    }

    /// @notice Checks if an account has permission to operate on the encrypted boolean value
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted boolean value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(ebool ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(ebool.unwrap(ctHash), account);
    }

    /// @notice Checks if an account has permission to operate on the encrypted 8-bit unsigned integer
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted uint8 value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(euint8 ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(euint8.unwrap(ctHash), account);
    }

    /// @notice Checks if an account has permission to operate on the encrypted 16-bit unsigned integer
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted uint16 value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(euint16 ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(euint16.unwrap(ctHash), account);
    }

    /// @notice Checks if an account has permission to operate on the encrypted 32-bit unsigned integer
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted uint32 value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(euint32 ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(euint32.unwrap(ctHash), account);
    }

    /// @notice Checks if an account has permission to operate on the encrypted 64-bit unsigned integer
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted uint64 value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(euint64 ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(euint64.unwrap(ctHash), account);
    }

    /// @notice Checks if an account has permission to operate on the encrypted 128-bit unsigned integer
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted uint128 value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(euint128 ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(euint128.unwrap(ctHash), account);
    }

    /// @notice Checks if an account has permission to operate on the encrypted 256-bit unsigned integer
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted uint256 value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(euint256 ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(euint256.unwrap(ctHash), account);
    }

    /// @notice Checks if an account has permission to operate on the encrypted address
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted address value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(eaddress ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(eaddress.unwrap(ctHash), account);
    }

    /// @notice Grants permission to the current contract to operate on the encrypted boolean value
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted boolean value to grant access to
    function allowThis(ebool ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(ebool.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the current contract to operate on the encrypted 8-bit unsigned integer
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted uint8 value to grant access to
    function allowThis(euint8 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint8.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the current contract to operate on the encrypted 16-bit unsigned integer
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted uint16 value to grant access to
    function allowThis(euint16 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint16.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the current contract to operate on the encrypted 32-bit unsigned integer
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted uint32 value to grant access to
    function allowThis(euint32 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint32.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the current contract to operate on the encrypted 64-bit unsigned integer
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted uint64 value to grant access to
    function allowThis(euint64 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint64.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the current contract to operate on the encrypted 128-bit unsigned integer
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted uint128 value to grant access to
    function allowThis(euint128 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint128.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the current contract to operate on the encrypted 256-bit unsigned integer
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted uint256 value to grant access to
    function allowThis(euint256 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint256.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the current contract to operate on the encrypted address
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted address value to grant access to
    function allowThis(eaddress ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(eaddress.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the message sender to operate on the encrypted boolean value
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted boolean value to grant access to
    function allowSender(ebool ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(ebool.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants permission to the message sender to operate on the encrypted 8-bit unsigned integer
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted uint8 value to grant access to
    function allowSender(euint8 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint8.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants permission to the message sender to operate on the encrypted 16-bit unsigned integer
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted uint16 value to grant access to
    function allowSender(euint16 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint16.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants permission to the message sender to operate on the encrypted 32-bit unsigned integer
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted uint32 value to grant access to
    function allowSender(euint32 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint32.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants permission to the message sender to operate on the encrypted 64-bit unsigned integer
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted uint64 value to grant access to
    function allowSender(euint64 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint64.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants permission to the message sender to operate on the encrypted 128-bit unsigned integer
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted uint128 value to grant access to
    function allowSender(euint128 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint128.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants permission to the message sender to operate on the encrypted 256-bit unsigned integer
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted uint256 value to grant access to
    function allowSender(euint256 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint256.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants permission to the message sender to operate on the encrypted address
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted address value to grant access to
    function allowSender(eaddress ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(eaddress.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted boolean value
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted boolean value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(ebool ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(ebool.unwrap(ctHash), account);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted 8-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted uint8 value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(euint8 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(euint8.unwrap(ctHash), account);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted 16-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted uint16 value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(euint16 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(euint16.unwrap(ctHash), account);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted 32-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted uint32 value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(euint32 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(euint32.unwrap(ctHash), account);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted 64-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted uint64 value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(euint64 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(euint64.unwrap(ctHash), account);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted 128-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted uint128 value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(euint128 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(euint128.unwrap(ctHash), account);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted 256-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted uint256 value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(euint256 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(euint256.unwrap(ctHash), account);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted address
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted address value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(eaddress ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(eaddress.unwrap(ctHash), account);
    }


}
// ********** BINDING DEFS ************* //

using BindingsEbool for ebool global;
library BindingsEbool {

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return the result of the eq
    function eq(ebool lhs, ebool rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return the result of the ne
    function ne(ebool lhs, ebool rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }

    /// @notice Performs the not operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type ebool
    /// @return the result of the not
    function not(ebool lhs) internal returns (ebool) {
        return FHE.not(lhs);
    }

    /// @notice Performs the and operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return the result of the and
    function and(ebool lhs, ebool rhs) internal returns (ebool) {
        return FHE.and(lhs, rhs);
    }

    /// @notice Performs the or operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return the result of the or
    function or(ebool lhs, ebool rhs) internal returns (ebool) {
        return FHE.or(lhs, rhs);
    }

    /// @notice Performs the xor operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return the result of the xor
    function xor(ebool lhs, ebool rhs) internal returns (ebool) {
        return FHE.xor(lhs, rhs);
    }
    function toU8(ebool value) internal returns (euint8) {
        return FHE.asEuint8(value);
    }
    function toU16(ebool value) internal returns (euint16) {
        return FHE.asEuint16(value);
    }
    function toU32(ebool value) internal returns (euint32) {
        return FHE.asEuint32(value);
    }
    function toU64(ebool value) internal returns (euint64) {
        return FHE.asEuint64(value);
    }
    function toU128(ebool value) internal returns (euint128) {
        return FHE.asEuint128(value);
    }
    function toU256(ebool value) internal returns (euint256) {
        return FHE.asEuint256(value);
    }
    function decrypt(ebool value) internal {
        FHE.decrypt(value);
    }
    function allow(ebool ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(ebool ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(ebool ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(ebool ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(ebool ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(ebool ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

using BindingsEuint8 for euint8 global;
library BindingsEuint8 {

    /// @notice Performs the add operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the add
    function add(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.add(lhs, rhs);
    }

    /// @notice Performs the mul operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the mul
    function mul(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.mul(lhs, rhs);
    }

    /// @notice Performs the div operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the div
    function div(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.div(lhs, rhs);
    }

    /// @notice Performs the sub operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the sub
    function sub(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.sub(lhs, rhs);
    }

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the eq
    function eq(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the ne
    function ne(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }

    /// @notice Performs the not operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @return the result of the not
    function not(euint8 lhs) internal returns (euint8) {
        return FHE.not(lhs);
    }

    /// @notice Performs the and operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the and
    function and(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.and(lhs, rhs);
    }

    /// @notice Performs the or operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the or
    function or(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.or(lhs, rhs);
    }

    /// @notice Performs the xor operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the xor
    function xor(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.xor(lhs, rhs);
    }

    /// @notice Performs the gt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the gt
    function gt(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return FHE.gt(lhs, rhs);
    }

    /// @notice Performs the gte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the gte
    function gte(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return FHE.gte(lhs, rhs);
    }

    /// @notice Performs the lt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the lt
    function lt(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return FHE.lt(lhs, rhs);
    }

    /// @notice Performs the lte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the lte
    function lte(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return FHE.lte(lhs, rhs);
    }

    /// @notice Performs the rem operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the rem
    function rem(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.rem(lhs, rhs);
    }

    /// @notice Performs the max operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the max
    function max(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.max(lhs, rhs);
    }

    /// @notice Performs the min operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the min
    function min(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.min(lhs, rhs);
    }

    /// @notice Performs the shl operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the shl
    function shl(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.shl(lhs, rhs);
    }

    /// @notice Performs the shr operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the shr
    function shr(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.shr(lhs, rhs);
    }

    /// @notice Performs the rol operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the rol
    function rol(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.rol(lhs, rhs);
    }

    /// @notice Performs the ror operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the ror
    function ror(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.ror(lhs, rhs);
    }

    /// @notice Performs the square operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @return the result of the square
    function square(euint8 lhs) internal returns (euint8) {
        return FHE.square(lhs);
    }
    function toBool(euint8 value) internal  returns (ebool) {
        return FHE.asEbool(value);
    }
    function toU16(euint8 value) internal returns (euint16) {
        return FHE.asEuint16(value);
    }
    function toU32(euint8 value) internal returns (euint32) {
        return FHE.asEuint32(value);
    }
    function toU64(euint8 value) internal returns (euint64) {
        return FHE.asEuint64(value);
    }
    function toU128(euint8 value) internal returns (euint128) {
        return FHE.asEuint128(value);
    }
    function toU256(euint8 value) internal returns (euint256) {
        return FHE.asEuint256(value);
    }
    function decrypt(euint8 value) internal {
        FHE.decrypt(value);
    }
    function allow(euint8 ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(euint8 ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(euint8 ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(euint8 ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(euint8 ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(euint8 ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

using BindingsEuint16 for euint16 global;
library BindingsEuint16 {

    /// @notice Performs the add operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the add
    function add(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.add(lhs, rhs);
    }

    /// @notice Performs the mul operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the mul
    function mul(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.mul(lhs, rhs);
    }

    /// @notice Performs the div operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the div
    function div(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.div(lhs, rhs);
    }

    /// @notice Performs the sub operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the sub
    function sub(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.sub(lhs, rhs);
    }

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the eq
    function eq(euint16 lhs, euint16 rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the ne
    function ne(euint16 lhs, euint16 rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }

    /// @notice Performs the not operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @return the result of the not
    function not(euint16 lhs) internal returns (euint16) {
        return FHE.not(lhs);
    }

    /// @notice Performs the and operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the and
    function and(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.and(lhs, rhs);
    }

    /// @notice Performs the or operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the or
    function or(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.or(lhs, rhs);
    }

    /// @notice Performs the xor operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the xor
    function xor(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.xor(lhs, rhs);
    }

    /// @notice Performs the gt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the gt
    function gt(euint16 lhs, euint16 rhs) internal returns (ebool) {
        return FHE.gt(lhs, rhs);
    }

    /// @notice Performs the gte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the gte
    function gte(euint16 lhs, euint16 rhs) internal returns (ebool) {
        return FHE.gte(lhs, rhs);
    }

    /// @notice Performs the lt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the lt
    function lt(euint16 lhs, euint16 rhs) internal returns (ebool) {
        return FHE.lt(lhs, rhs);
    }

    /// @notice Performs the lte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the lte
    function lte(euint16 lhs, euint16 rhs) internal returns (ebool) {
        return FHE.lte(lhs, rhs);
    }

    /// @notice Performs the rem operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the rem
    function rem(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.rem(lhs, rhs);
    }

    /// @notice Performs the max operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the max
    function max(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.max(lhs, rhs);
    }

    /// @notice Performs the min operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the min
    function min(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.min(lhs, rhs);
    }

    /// @notice Performs the shl operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the shl
    function shl(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.shl(lhs, rhs);
    }

    /// @notice Performs the shr operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the shr
    function shr(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.shr(lhs, rhs);
    }

    /// @notice Performs the rol operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the rol
    function rol(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.rol(lhs, rhs);
    }

    /// @notice Performs the ror operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the ror
    function ror(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.ror(lhs, rhs);
    }

    /// @notice Performs the square operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @return the result of the square
    function square(euint16 lhs) internal returns (euint16) {
        return FHE.square(lhs);
    }
    function toBool(euint16 value) internal  returns (ebool) {
        return FHE.asEbool(value);
    }
    function toU8(euint16 value) internal returns (euint8) {
        return FHE.asEuint8(value);
    }
    function toU32(euint16 value) internal returns (euint32) {
        return FHE.asEuint32(value);
    }
    function toU64(euint16 value) internal returns (euint64) {
        return FHE.asEuint64(value);
    }
    function toU128(euint16 value) internal returns (euint128) {
        return FHE.asEuint128(value);
    }
    function toU256(euint16 value) internal returns (euint256) {
        return FHE.asEuint256(value);
    }
    function decrypt(euint16 value) internal {
        FHE.decrypt(value);
    }
    function allow(euint16 ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(euint16 ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(euint16 ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(euint16 ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(euint16 ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(euint16 ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

using BindingsEuint32 for euint32 global;
library BindingsEuint32 {

    /// @notice Performs the add operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the add
    function add(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.add(lhs, rhs);
    }

    /// @notice Performs the mul operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the mul
    function mul(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.mul(lhs, rhs);
    }

    /// @notice Performs the div operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the div
    function div(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.div(lhs, rhs);
    }

    /// @notice Performs the sub operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the sub
    function sub(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.sub(lhs, rhs);
    }

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the eq
    function eq(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the ne
    function ne(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }

    /// @notice Performs the not operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @return the result of the not
    function not(euint32 lhs) internal returns (euint32) {
        return FHE.not(lhs);
    }

    /// @notice Performs the and operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the and
    function and(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.and(lhs, rhs);
    }

    /// @notice Performs the or operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the or
    function or(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.or(lhs, rhs);
    }

    /// @notice Performs the xor operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the xor
    function xor(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.xor(lhs, rhs);
    }

    /// @notice Performs the gt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the gt
    function gt(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return FHE.gt(lhs, rhs);
    }

    /// @notice Performs the gte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the gte
    function gte(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return FHE.gte(lhs, rhs);
    }

    /// @notice Performs the lt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the lt
    function lt(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return FHE.lt(lhs, rhs);
    }

    /// @notice Performs the lte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the lte
    function lte(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return FHE.lte(lhs, rhs);
    }

    /// @notice Performs the rem operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the rem
    function rem(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.rem(lhs, rhs);
    }

    /// @notice Performs the max operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the max
    function max(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.max(lhs, rhs);
    }

    /// @notice Performs the min operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the min
    function min(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.min(lhs, rhs);
    }

    /// @notice Performs the shl operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the shl
    function shl(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.shl(lhs, rhs);
    }

    /// @notice Performs the shr operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the shr
    function shr(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.shr(lhs, rhs);
    }

    /// @notice Performs the rol operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the rol
    function rol(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.rol(lhs, rhs);
    }

    /// @notice Performs the ror operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the ror
    function ror(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.ror(lhs, rhs);
    }

    /// @notice Performs the square operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @return the result of the square
    function square(euint32 lhs) internal returns (euint32) {
        return FHE.square(lhs);
    }
    function toBool(euint32 value) internal  returns (ebool) {
        return FHE.asEbool(value);
    }
    function toU8(euint32 value) internal returns (euint8) {
        return FHE.asEuint8(value);
    }
    function toU16(euint32 value) internal returns (euint16) {
        return FHE.asEuint16(value);
    }
    function toU64(euint32 value) internal returns (euint64) {
        return FHE.asEuint64(value);
    }
    function toU128(euint32 value) internal returns (euint128) {
        return FHE.asEuint128(value);
    }
    function toU256(euint32 value) internal returns (euint256) {
        return FHE.asEuint256(value);
    }
    function decrypt(euint32 value) internal {
        FHE.decrypt(value);
    }
    function allow(euint32 ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(euint32 ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(euint32 ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(euint32 ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(euint32 ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(euint32 ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

using BindingsEuint64 for euint64 global;
library BindingsEuint64 {

    /// @notice Performs the add operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the add
    function add(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.add(lhs, rhs);
    }

    /// @notice Performs the mul operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the mul
    function mul(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.mul(lhs, rhs);
    }

    /// @notice Performs the sub operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the sub
    function sub(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.sub(lhs, rhs);
    }

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the eq
    function eq(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the ne
    function ne(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }

    /// @notice Performs the not operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @return the result of the not
    function not(euint64 lhs) internal returns (euint64) {
        return FHE.not(lhs);
    }

    /// @notice Performs the and operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the and
    function and(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.and(lhs, rhs);
    }

    /// @notice Performs the or operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the or
    function or(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.or(lhs, rhs);
    }

    /// @notice Performs the xor operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the xor
    function xor(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.xor(lhs, rhs);
    }

    /// @notice Performs the gt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the gt
    function gt(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return FHE.gt(lhs, rhs);
    }

    /// @notice Performs the gte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the gte
    function gte(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return FHE.gte(lhs, rhs);
    }

    /// @notice Performs the lt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the lt
    function lt(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return FHE.lt(lhs, rhs);
    }

    /// @notice Performs the lte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the lte
    function lte(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return FHE.lte(lhs, rhs);
    }

    /// @notice Performs the max operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the max
    function max(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.max(lhs, rhs);
    }

    /// @notice Performs the min operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the min
    function min(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.min(lhs, rhs);
    }

    /// @notice Performs the shl operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the shl
    function shl(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.shl(lhs, rhs);
    }

    /// @notice Performs the shr operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the shr
    function shr(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.shr(lhs, rhs);
    }

    /// @notice Performs the rol operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the rol
    function rol(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.rol(lhs, rhs);
    }

    /// @notice Performs the ror operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the ror
    function ror(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.ror(lhs, rhs);
    }

    /// @notice Performs the square operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @return the result of the square
    function square(euint64 lhs) internal returns (euint64) {
        return FHE.square(lhs);
    }
    function toBool(euint64 value) internal  returns (ebool) {
        return FHE.asEbool(value);
    }
    function toU8(euint64 value) internal returns (euint8) {
        return FHE.asEuint8(value);
    }
    function toU16(euint64 value) internal returns (euint16) {
        return FHE.asEuint16(value);
    }
    function toU32(euint64 value) internal returns (euint32) {
        return FHE.asEuint32(value);
    }
    function toU128(euint64 value) internal returns (euint128) {
        return FHE.asEuint128(value);
    }
    function toU256(euint64 value) internal returns (euint256) {
        return FHE.asEuint256(value);
    }
    function decrypt(euint64 value) internal {
        FHE.decrypt(value);
    }
    function allow(euint64 ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(euint64 ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(euint64 ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(euint64 ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(euint64 ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(euint64 ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

using BindingsEuint128 for euint128 global;
library BindingsEuint128 {

    /// @notice Performs the add operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the add
    function add(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.add(lhs, rhs);
    }

    /// @notice Performs the sub operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the sub
    function sub(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.sub(lhs, rhs);
    }

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the eq
    function eq(euint128 lhs, euint128 rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the ne
    function ne(euint128 lhs, euint128 rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }

    /// @notice Performs the not operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @return the result of the not
    function not(euint128 lhs) internal returns (euint128) {
        return FHE.not(lhs);
    }

    /// @notice Performs the and operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the and
    function and(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.and(lhs, rhs);
    }

    /// @notice Performs the or operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the or
    function or(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.or(lhs, rhs);
    }

    /// @notice Performs the xor operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the xor
    function xor(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.xor(lhs, rhs);
    }

    /// @notice Performs the gt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the gt
    function gt(euint128 lhs, euint128 rhs) internal returns (ebool) {
        return FHE.gt(lhs, rhs);
    }

    /// @notice Performs the gte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the gte
    function gte(euint128 lhs, euint128 rhs) internal returns (ebool) {
        return FHE.gte(lhs, rhs);
    }

    /// @notice Performs the lt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the lt
    function lt(euint128 lhs, euint128 rhs) internal returns (ebool) {
        return FHE.lt(lhs, rhs);
    }

    /// @notice Performs the lte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the lte
    function lte(euint128 lhs, euint128 rhs) internal returns (ebool) {
        return FHE.lte(lhs, rhs);
    }

    /// @notice Performs the max operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the max
    function max(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.max(lhs, rhs);
    }

    /// @notice Performs the min operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the min
    function min(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.min(lhs, rhs);
    }

    /// @notice Performs the shl operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the shl
    function shl(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.shl(lhs, rhs);
    }

    /// @notice Performs the shr operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the shr
    function shr(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.shr(lhs, rhs);
    }

    /// @notice Performs the rol operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the rol
    function rol(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.rol(lhs, rhs);
    }

    /// @notice Performs the ror operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the ror
    function ror(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.ror(lhs, rhs);
    }
    function toBool(euint128 value) internal  returns (ebool) {
        return FHE.asEbool(value);
    }
    function toU8(euint128 value) internal returns (euint8) {
        return FHE.asEuint8(value);
    }
    function toU16(euint128 value) internal returns (euint16) {
        return FHE.asEuint16(value);
    }
    function toU32(euint128 value) internal returns (euint32) {
        return FHE.asEuint32(value);
    }
    function toU64(euint128 value) internal returns (euint64) {
        return FHE.asEuint64(value);
    }
    function toU256(euint128 value) internal returns (euint256) {
        return FHE.asEuint256(value);
    }
    function decrypt(euint128 value) internal {
        FHE.decrypt(value);
    }
    function allow(euint128 ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(euint128 ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(euint128 ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(euint128 ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(euint128 ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(euint128 ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

using BindingsEuint256 for euint256 global;
library BindingsEuint256 {

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return the result of the eq
    function eq(euint256 lhs, euint256 rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return the result of the ne
    function ne(euint256 lhs, euint256 rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }
    function toBool(euint256 value) internal  returns (ebool) {
        return FHE.asEbool(value);
    }
    function toU8(euint256 value) internal returns (euint8) {
        return FHE.asEuint8(value);
    }
    function toU16(euint256 value) internal returns (euint16) {
        return FHE.asEuint16(value);
    }
    function toU32(euint256 value) internal returns (euint32) {
        return FHE.asEuint32(value);
    }
    function toU64(euint256 value) internal returns (euint64) {
        return FHE.asEuint64(value);
    }
    function toU128(euint256 value) internal returns (euint128) {
        return FHE.asEuint128(value);
    }
    function toEaddress(euint256 value) internal returns (eaddress) {
        return FHE.asEaddress(value);
    }
    function decrypt(euint256 value) internal {
        FHE.decrypt(value);
    }
    function allow(euint256 ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(euint256 ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(euint256 ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(euint256 ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(euint256 ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(euint256 ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

using BindingsEaddress for eaddress global;
library BindingsEaddress {

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type eaddress
    /// @param rhs second input of type eaddress
    /// @return the result of the eq
    function eq(eaddress lhs, eaddress rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type eaddress
    /// @param rhs second input of type eaddress
    /// @return the result of the ne
    function ne(eaddress lhs, eaddress rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }
    function toBool(eaddress value) internal  returns (ebool) {
        return FHE.asEbool(value);
    }
    function toU8(eaddress value) internal returns (euint8) {
        return FHE.asEuint8(value);
    }
    function toU16(eaddress value) internal returns (euint16) {
        return FHE.asEuint16(value);
    }
    function toU32(eaddress value) internal returns (euint32) {
        return FHE.asEuint32(value);
    }
    function toU64(eaddress value) internal returns (euint64) {
        return FHE.asEuint64(value);
    }
    function toU128(eaddress value) internal returns (euint128) {
        return FHE.asEuint128(value);
    }
    function toU256(eaddress value) internal returns (euint256) {
        return FHE.asEuint256(value);
    }
    function decrypt(eaddress value) internal {
        FHE.decrypt(value);
    }
    function allow(eaddress ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(eaddress ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(eaddress ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(eaddress ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(eaddress ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(eaddress ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}


// File contracts/Counter.sol

// Original license: SPDX_License_Identifier: UNLICENSED
pragma solidity ^0.8.25;

contract Counter {
    euint32 public count;
    euint32 public ONE;
    ebool public isInitialized;

    constructor() {
        ONE = FHE.asEuint32(1);
        count = FHE.asEuint32(0);

        isInitialized = FHE.asEbool(false);
        isInitialized = FHE.asEbool(true);

        FHE.allowThis(count);
        FHE.allowThis(ONE);

        FHE.gte(count, ONE);

        FHE.allowSender(count);
    }

    function increment() public {
        count = FHE.add(count, ONE);
        FHE.allowThis(count);
        FHE.allowSender(count);
    }

    function decrement() public {
        count = FHE.sub(count, ONE);
        FHE.allowThis(count);
        FHE.allowSender(count);
    }

    function reset(InEuint32 memory value) public {
        count = FHE.asEuint32(value);
        FHE.allowThis(count);
        FHE.allowSender(count);
    }

    function decryptCounter() public {
        FHE.decrypt(count);
    }

    function getDecryptedValue() external view returns(uint256) {
        (uint256 value, bool decrypted) = FHE.getDecryptResultSafe(count);
        if (!decrypted)
            revert("Value is not ready");

        return value;
    }    
}
