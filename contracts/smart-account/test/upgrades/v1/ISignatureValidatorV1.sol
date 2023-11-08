// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.20;

// bytes4(keccak256("isValidSignature(bytes32,bytes)")
bytes4 constant EIP1271_MAGIC_VALUE = 0x1626ba7e;

interface ISignatureValidatorV1 {
    /**
     * @dev Should return whether the signature provided is valid for the provided data
     * @param _dataHash Arbitrary length data signed on behalf of address(this)
     * @param _signature Signature byte array associated with _data
     *
     * MUST return the bytes4 magic value 0x1626ba7e when function passes.
     * MUST NOT modify state (using STATICCALL for solc < 0.5, view modifier for solc > 0.5)
     * MUST allow external calls
     */
    function isValidSignature(
        bytes32 _dataHash,
        bytes memory _signature
    ) external view returns (bytes4);
}
