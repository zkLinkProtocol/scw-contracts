// SPDX-License-Identifier: MIT

pragma solidity 0.8.17;

import {Base64URL} from "./Base64URL.sol";

/// @dev The type id of a single transaction signed by r1
bytes2 constant SINGLE_TX_R1_TYPE = 0xA000;
/// @dev The type id of the multi transactions signed by a single r1 key
bytes2 constant MULTI_TX_R1_TYPE = 0xB000;
/// @dev The type id of the multi transactions signed by a single k1 key
bytes2 constant MULTI_TX_K1_TYPE = 0xB001;

/// @dev The passkey types
enum PasskeyTypes {
    // 0: WebAuthn P-256
    Legacy,
    // 1: WebAuthn P-256 with turnkey payload
    Turnkey
}

library PasskeyHelper {
    bytes1 private constant AUTH_DATA_FLAGS_UP = 0x01; // Bit 0
    bytes1 private constant AUTH_DATA_FLAGS_UV = 0x04; // Bit 2
    bytes1 private constant AUTH_DATA_FLAGS_BE = 0x08; // Bit 3
    bytes1 private constant AUTH_DATA_FLAGS_BS = 0x10; // Bit 4

    /// @dev Calculate the P-256 signature parameters
    /// @param _hash The hash to verify
    /// @param encodedSignature The encoded signature
    /// @return Whether the signature is valid
    function calcP256SignatureParams(
        bytes32 _hash,
        bytes memory encodedSignature
    ) internal pure returns (uint256, uint256, uint256) {
        (
            uint256 r,
            uint256 s,
            uint8 _passkeyType,
            bytes memory authenticatorData,
            bool requireUserVerification,
            string memory clientDataJSONPrefix,
            string memory clientDataJSONSuffix,
            uint256 responseTypeLocation,
            string memory turnkeyPayloadPrefix,
            string memory turnkeyPayloadSuffix
        ) = decodeWebAuthnP256Signature(encodedSignature);

        bytes memory challenge;
        PasskeyTypes passkeyType = PasskeyTypes(_passkeyType);

        if (passkeyType == PasskeyTypes.Legacy) {
            challenge = PasskeyHelper.bytesToHex(abi.encodePacked(_hash));
        } else if (passkeyType == PasskeyTypes.Turnkey) {
            string memory hashString = string(
                abi.encodePacked(
                    "0x",
                    PasskeyHelper.bytesToHex(abi.encodePacked(_hash))
                )
            );
            challenge = PasskeyHelper.bytesToHex(
                abi.encodePacked(
                    sha256(
                        (
                            abi.encodePacked(
                                string.concat(
                                    turnkeyPayloadPrefix,
                                    hashString,
                                    turnkeyPayloadSuffix
                                )
                            )
                        )
                    )
                )
            );
        }

        if (
            authenticatorData.length < 37 ||
            !PasskeyHelper.checkAuthFlags(
                authenticatorData[32],
                requireUserVerification
            )
        ) {
            return (0, 0, 0);
        }

        bytes memory clientDataJSON = abi.encodePacked(
            clientDataJSONPrefix,
            Base64URL.encode(challenge),
            clientDataJSONSuffix
        );

        // Check that response is for an authentication assertion
        /* eslint-disable-next-line no-alert, quotes, semi*/
        string memory responseType = '"type":"webauthn.get"';
        if (
            !PasskeyHelper.contains(
                responseType,
                string(clientDataJSON),
                responseTypeLocation
            )
        ) {
            return (0, 0, 0);
        }

        // Check that the public key signed sha256(authenticatorData || sha256(clientDataJSON))
        bytes32 clientDataJSONHash = sha256(bytes(clientDataJSON));
        bytes32 messageHash = sha256(
            abi.encodePacked(authenticatorData, clientDataJSONHash)
        );

        return (r, s, uint256(messageHash));
    }

    /// @dev Decode a WebAuthn P-256 signature
    /// @param _signature The signature to decode
    function decodeWebAuthnP256Signature(
        bytes memory _signature
    )
        internal
        pure
        returns (
            uint256 r,
            uint256 s,
            uint8 passkeyType,
            bytes memory authenticatorData,
            bool requireUserVerification,
            string memory clientDataJSONPrefix,
            string memory clientDataJSONSuffix,
            uint256 responseTypeLocation,
            string memory turnkeyPayloadPrefix,
            string memory turnkeyPayloadSuffix
        )
    {
        (
            r,
            s,
            passkeyType,
            authenticatorData,
            requireUserVerification,
            clientDataJSONPrefix,
            clientDataJSONSuffix,
            responseTypeLocation,
            turnkeyPayloadPrefix,
            turnkeyPayloadSuffix
        ) = abi.decode(
            _signature,
            (
                uint256,
                uint256,
                uint8,
                bytes,
                bool,
                string,
                string,
                uint256,
                string,
                string
            )
        );
    }

    function bytesToHex(
        bytes memory buffer
    ) internal pure returns (bytes memory) {
        // Fixed buffer size for hexadecimal conversion
        bytes memory converted = new bytes(buffer.length * 2);

        bytes memory _base = "0123456789abcdef";

        for (uint256 i = 0; i < buffer.length; i++) {
            converted[i * 2] = _base[uint8(buffer[i] >> 4)];
            converted[i * 2 + 1] = _base[uint8(buffer[i] & 0x0f)];
        }
        return converted;
    }

    /// Verifies the authFlags in authenticatorData. Numbers in inline comment
    /// correspond to the same numbered bullets in
    /// https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion.
    function checkAuthFlags(
        bytes1 flags,
        bool requireUserVerification
    ) internal pure returns (bool) {
        // 17. Verify that the UP bit of the flags in authData is set.
        if (flags & AUTH_DATA_FLAGS_UP != AUTH_DATA_FLAGS_UP) {
            return false;
        }
        // 18. If user verification was determined to be required, verify that
        // the UV bit of the flags in authData is set. Otherwise, ignore the
        // value of the UV flag.
        if (
            requireUserVerification &&
            (flags & AUTH_DATA_FLAGS_UV) != AUTH_DATA_FLAGS_UV
        ) {
            return false;
        }

        // 19. If the BE bit of the flags in authData is not set, verify that
        // the BS bit is not set.
        if (flags & AUTH_DATA_FLAGS_BE != AUTH_DATA_FLAGS_BE) {
            if (flags & AUTH_DATA_FLAGS_BS == AUTH_DATA_FLAGS_BS) {
                return false;
            }
        }

        return true;
    }

    function contains(
        string memory substr,
        string memory str,
        uint256 location
    ) internal pure returns (bool) {
        bytes memory substrBytes = bytes(substr);
        bytes memory strBytes = bytes(str);

        uint256 substrLen = substrBytes.length;
        uint256 strLen = strBytes.length;

        for (uint256 i = 0; i < substrLen; i++) {
            if (location + i >= strLen) {
                return false;
            }

            if (substrBytes[i] != strBytes[location + i]) {
                return false;
            }
        }

        return true;
    }
}
