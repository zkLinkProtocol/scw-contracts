// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {BaseAuthorizationModule} from "./BaseAuthorizationModule.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Secp256r1, PassKeyId} from "./PasskeyValidationModules/Secp256r1.sol";
import {PasskeyHelper, SINGLE_TX_R1_TYPE, MULTI_TX_R1_TYPE, MULTI_TX_K1_TYPE} from "./PasskeyValidationModules/PasskeyHelper.sol";

contract EcdsaAndPasskeyOwnershipRegistryModule is BaseAuthorizationModule {
    using ECDSA for bytes32;

    struct ChainDomain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    struct UserOperationHash {
        bytes32 txHash;
    }

    /// @notice The EIP-712 typehash for the contract's domain
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId)");
    bytes32 private constant USER_OPERATION_HASH_TYPEHASH =
        keccak256("UserOperationHash(bytes32 txHash)");
    bytes32 private constant CHAIN_DOMAIN_TYPEHASH =
        keccak256(
            "ChainDomain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    bytes32 private constant MULTI_TRANSACTION_TYPEHASH =
        keccak256(
            "MultiTransaction(TransactionHash[] transactionHashes,UserOperationHash[] userOpHashes,ChainDomain[] userOpDomains)ChainDomain(string name,string version,uint256 chainId,address verifyingContract)TransactionHash(bytes32 txHash)UserOperationHash(bytes32 txHash)"
        );
    bytes32 private constant MULTI_TRANSACTION_EIP712_DOMAIN_NAME =
        keccak256("ZKLink Nova Multi Transaction Validator");
    bytes32 private constant MULTI_TRANSACTION_EIP712_DOMAIN_VERSION =
        keccak256("0.1.0");
    uint256 private immutable MULTI_TRANSACTION_EIP712_DOMAIN_CHAIN_ID;

    string public constant NAME = "ECDSA And Passkey Ownership Registry Module";
    string public constant VERSION = "0.1.0";

    mapping(address => address) internal _smartAccountOwners;
    mapping(address => address) internal _smartAccountTurnkey;
    mapping(address => PassKeyId) internal _smartAccountPassKeys;

    event OwnershipTransferred(
        address indexed smartAccount,
        address indexed oldOwner,
        address indexed newOwner
    );

    event TurnkeyWalletTransferred(
        address indexed smartAccount,
        address indexed oldTurnkeyWallet,
        address indexed newTurnkeyWallet
    );

    event PasskeyTransferred(
        address indexed smartAccount,
        string oldCredentialIdHash,
        string newCredentialIdHash
    );

    error NoOwnerRegisteredForSmartAccount(address smartAccount);
    error NoTurnkeyWalletRegisteredForSmartAccount(address smartAccount);
    error NoRequiredSignerRegisteredForSmartAccount(address smartAccount);
    error AlreadyInitedForSmartAccount(address smartAccount);
    error NoPassKeyRegisteredForSmartAccount(address smartAccount);
    error WrongSignatureLength();
    error NotEOA(address account);
    error ZeroAddressNotAllowedAsOwner();
    error ZeroAddressNotAllowedAsTurnkeyWallet();
    error ZeroNotAllowedAsPublicKey();

    constructor(uint256 _chainId) {
        // Set the chain ID for the EIP-712 domain.
        MULTI_TRANSACTION_EIP712_DOMAIN_CHAIN_ID = _chainId;
    }

    /**
     * @dev Initializes the module for a Smart Account.
     * Should be used at a time of first enabling the module for a Smart Account.
     * @param eoaOwner The owner of the Smart Account. Should be EOA!
     * @param turnkeyWallet The turnkey wallet of the Smart Account. Should be EOA!
     * @param _pubKeyX The x-coordinate of the public key.
     * @param _pubKeyY The y-coordinate of the public key.
     * @param _credentialIdHash The credentialIdHash of public key.
     */
    function initForSmartAccount(
        address eoaOwner,
        address turnkeyWallet,
        uint256 _pubKeyX,
        uint256 _pubKeyY,
        string memory _credentialIdHash
    ) external returns (address) {
        if (_smartAccountOwners[msg.sender] != address(0))
            revert AlreadyInitedForSmartAccount(msg.sender);
        if (eoaOwner == address(0)) revert ZeroAddressNotAllowedAsOwner();
        if (turnkeyWallet == address(0))
            revert ZeroAddressNotAllowedAsTurnkeyWallet();
        _smartAccountOwners[msg.sender] = eoaOwner;
        _smartAccountTurnkey[msg.sender] = turnkeyWallet;

        if (
            _smartAccountPassKeys[msg.sender].pubKeyX != 0 &&
            _smartAccountPassKeys[msg.sender].pubKeyY != 0
        ) revert AlreadyInitedForSmartAccount(msg.sender);
        _smartAccountPassKeys[msg.sender] = PassKeyId(
            _pubKeyX,
            _pubKeyY,
            _credentialIdHash
        );

        return address(this);
    }

    /**
     * @dev Sets/changes an for a Smart Account.
     * Should be called by Smart Account itself.
     * @param owner The owner of the Smart Account.
     */
    function transferOwnership(address owner) external {
        if (_isSmartContract(owner)) revert NotEOA(owner);
        if (owner == address(0)) revert ZeroAddressNotAllowedAsOwner();
        _transferOwnership(msg.sender, owner);
    }

    /**
     * @dev Renounces ownership
     * should be called by Smart Account.
     */
    function renounceOwnership() external {
        _transferOwnership(msg.sender, address(0));
    }

    /**
     * @dev Sets/changes an turnkey wallet for a Smart Account.
     * Should be called by Smart Account itself.
     * @param turnkeyWallet The turnkey wallet of the Smart Account.
     */
    function transferTurnkeyWallet(address turnkeyWallet) external {
        if (_isSmartContract(turnkeyWallet)) revert NotEOA(turnkeyWallet);
        if (turnkeyWallet == address(0))
            revert ZeroAddressNotAllowedAsTurnkeyWallet();
        _transferTurnkeyWallet(msg.sender, turnkeyWallet);
    }

    /**
     * @dev Sets/changes an passkey for a Smart Account.
     * Should be called by Smart Account itself.
     * @param _pubKeyX The x-coordinate of the public key.
     * @param _pubKeyY The y-coordinate of the public key.
     * @param _credentialIdHash The credentialIdHash of the public key.
     */
    function transferPasskey(
        uint256 _pubKeyX,
        uint256 _pubKeyY,
        string memory _credentialIdHash
    ) external {
        if (_pubKeyX == 0 || _pubKeyY == 0) revert ZeroNotAllowedAsPublicKey();
        _transferPasskey(msg.sender, _pubKeyX, _pubKeyY, _credentialIdHash);
    }

    /**
     * @dev Returns the owner of the Smart Account. Reverts for Smart Accounts without owners.
     * @param smartAccount Smart Account address.
     * @return owner The owner of the Smart Account.
     */
    function getOwner(address smartAccount) external view returns (address) {
        address owner = _smartAccountOwners[smartAccount];
        if (owner == address(0))
            revert NoOwnerRegisteredForSmartAccount(smartAccount);
        return owner;
    }

    /**
     * @dev Returns the turnkey wallet of the Smart Account. Reverts for Smart Accounts without turnkey wallets.
     * @param smartAccount Smart Account address.
     * @return turnkeyWallet The turnkey wallet of the Smart Account.
     */
    function getTurnkeyWallet(
        address smartAccount
    ) external view returns (address) {
        address turnkeyWallet = _smartAccountTurnkey[smartAccount];
        if (turnkeyWallet == address(0))
            revert NoTurnkeyWalletRegisteredForSmartAccount(smartAccount);
        return turnkeyWallet;
    }

    /**
     * @dev Returns the passkey of the Smart Account. Reverts for Smart Accounts without passkeys.
     * @param smartAccount Smart Account address.
     * @return passKey The passkey of the Smart Account.
     */
    function getPasskey(
        address smartAccount
    ) external view returns (PassKeyId memory) {
        PassKeyId memory passKey = _smartAccountPassKeys[smartAccount];
        if (passKey.pubKeyX == 0 || passKey.pubKeyY == 0)
            revert NoPassKeyRegisteredForSmartAccount(smartAccount);
        return passKey;
    }

    /**
     * @dev validates userOperation
     * @param userOp User Operation to be validated.
     * @param userOpHash Hash of the User Operation to be validated.
     * @return sigValidationResult 0 if signature is valid, SIG_VALIDATION_FAILED otherwise.
     */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) external view virtual returns (uint256) {
        (bytes memory userOpSignature, ) = abi.decode(
            userOp.signature,
            (bytes, address)
        );

        bool bIsValidSignature;

        if (userOpSignature.length == 65) {
            bIsValidSignature = _verifyK1Signature(
                userOpHash,
                userOpSignature,
                userOp.sender
            );
        } else if (userOpSignature.length > 65) {
            (bytes2 magicNum, bytes memory encodedSignature) = abi.decode(
                userOpSignature,
                (bytes2, bytes)
            );

            if (magicNum == SINGLE_TX_R1_TYPE) {
                bIsValidSignature = _verifyR1Signature(
                    userOpHash,
                    encodedSignature,
                    msg.sender
                );
            } else if (magicNum == MULTI_TX_R1_TYPE) {
                (
                    bytes32 rootHash,
                    bytes memory passkeySignature
                ) = _decodeMultiTxRootHashAndSignature(
                        userOpHash,
                        encodedSignature
                    );

                bIsValidSignature = _verifyR1Signature(
                    rootHash,
                    passkeySignature,
                    msg.sender
                );
            } else if (magicNum == MULTI_TX_K1_TYPE) {
                (
                    bytes32 rootHash,
                    bytes memory signature
                ) = _decodeMultiTxRootHashAndSignature(
                        userOpHash,
                        encodedSignature
                    );
                bIsValidSignature = _verifyK1Signature(
                    rootHash,
                    signature,
                    userOp.sender
                );
            }
        }

        if (bIsValidSignature) return VALIDATION_SUCCESS;

        return SIG_VALIDATION_FAILED;
    }

    /**
     * @dev Validates a signature for a message.
     * To be called from a Smart Account.
     * @param dataHash Exact hash of the data that was signed.
     * @param moduleSignature Signature to be validated.
     * @return EIP1271_MAGIC_VALUE if signature is valid, 0xffffffff otherwise.
     */
    function isValidSignature(
        bytes32 dataHash,
        bytes memory moduleSignature
    ) public view virtual override returns (bytes4) {
        return
            isValidSignatureForAddress(dataHash, moduleSignature, msg.sender);
    }

    /**
     * @dev Validates a signature for a message signed by address.
     * @dev Also try dataHash.toEthSignedMessageHash()
     * @param dataHash hash of the data
     * @param moduleSignature Signature to be validated.
     * @param smartAccount expected signer Smart Account address.
     * @return EIP1271_MAGIC_VALUE if signature is valid, 0xffffffff otherwise.
     */
    function isValidSignatureForAddress(
        bytes32 dataHash,
        bytes memory moduleSignature,
        address smartAccount
    ) public view virtual returns (bytes4) {
        if (_verifyK1Signature(dataHash, moduleSignature, smartAccount)) {
            return EIP1271_MAGIC_VALUE;
        }
        return bytes4(0xffffffff);
    }

    /**
     * @dev Transfers ownership for smartAccount and emits an event
     * @param newOwner Smart Account address.
     */
    function _transferOwnership(
        address smartAccount,
        address newOwner
    ) internal {
        address _oldOwner = _smartAccountOwners[smartAccount];
        _smartAccountOwners[smartAccount] = newOwner;
        emit OwnershipTransferred(smartAccount, _oldOwner, newOwner);
    }

    /**
     * @dev Transfers turnkey wallet for smartAccount and emits an event
     * @param newTurnkeyWallet Smart Account address.
     */
    function _transferTurnkeyWallet(
        address smartAccount,
        address newTurnkeyWallet
    ) internal {
        address _oldTurnkeyWallet = _smartAccountTurnkey[smartAccount];
        _smartAccountTurnkey[smartAccount] = newTurnkeyWallet;
        emit TurnkeyWalletTransferred(
            smartAccount,
            _oldTurnkeyWallet,
            newTurnkeyWallet
        );
    }

    /**
     * @dev Transfers passkey for smartAccount and emits an event
     * @param smartAccount Smart Account address.
     * @param _pubKeyX The x-coordinate of the public key.
     * @param _pubKeyY The y-coordinate of the public key.
     * @param _credentialIdHash The credentialIdHash of the public key.
     */
    function _transferPasskey(
        address smartAccount,
        uint256 _pubKeyX,
        uint256 _pubKeyY,
        string memory _credentialIdHash
    ) internal {
        PassKeyId memory oldPasskey = _smartAccountPassKeys[smartAccount];
        string memory oldCredentialIdHash = oldPasskey.keyId;
        _smartAccountPassKeys[smartAccount] = PassKeyId(
            _pubKeyX,
            _pubKeyY,
            _credentialIdHash
        );

        emit PasskeyTransferred(
            smartAccount,
            oldCredentialIdHash,
            _credentialIdHash
        );
    }

    /**
     * @dev Validates a k1 signature for a message.
     * @dev Check if signature was made over dataHash.toEthSignedMessageHash() or just dataHash
     * The former is for personal_sign, the latter for the typed_data sign
     * Only EOA owners supported, no Smart Account Owners
     * For Smart Contract Owners check SmartContractOwnership Module instead
     * @param dataHash Hash of the data to be validated.
     * @param signature Signature to be validated.
     * @param smartAccount expected signer Smart Account address.
     * @return true if signature is valid, false otherwise.
     */
    function _verifyK1Signature(
        bytes32 dataHash,
        bytes memory signature,
        address smartAccount
    ) internal view returns (bool) {
        address expectedSigner = _smartAccountOwners[smartAccount];
        address turnkeySigner = _smartAccountTurnkey[smartAccount];
        if (expectedSigner == address(0) || turnkeySigner == address(0))
            revert NoRequiredSignerRegisteredForSmartAccount(smartAccount);
        if (signature.length < 65) revert WrongSignatureLength();
        address recovered = (dataHash.toEthSignedMessageHash()).recover(
            signature
        );
        if (expectedSigner == recovered) {
            return true;
        }
        if (turnkeySigner == recovered) {
            return true;
        }
        recovered = dataHash.recover(signature);
        if (expectedSigner == recovered) {
            return true;
        }
        if (turnkeySigner == recovered) {
            return true;
        }

        return false;
    }

    /**
     * @dev Validates a r1 signature for a message.
     * @param dataHash Hash of the data to be validated.
     * @param signature Signature to be validated.
     * @param smartAccount expected signer Smart Account address.
     * @return true if signature is valid, false otherwise.
     */
    function _verifyR1Signature(
        bytes32 dataHash,
        bytes memory signature,
        address smartAccount
    ) internal view returns (bool) {
        PassKeyId memory passkey = _smartAccountPassKeys[smartAccount];
        if (passkey.pubKeyX == 0 && passkey.pubKeyY == 0)
            revert NoPassKeyRegisteredForSmartAccount(smartAccount);

        (uint256 r, uint256 s, uint256 e) = PasskeyHelper
            .calcP256SignatureParams(dataHash, signature);

        if (r == 0 && s == 0 && e == 0) return false;
        return Secp256r1.verify(passkey, r, s, e);
    }

    /// @notice Decode the root hash and signature for the multi transaction.
    /// @param _userOpHash The hash of the user operation.
    /// @param _encodedSignature The encoded signature.
    function _decodeMultiTxRootHashAndSignature(
        bytes32 _userOpHash,
        bytes memory _encodedSignature
    ) internal view returns (bytes32 rootHash, bytes memory signature) {
        (
            bytes32 novaTxsRootHash,
            bytes memory userOpsHashPrefix,
            bytes memory userOpsHashSuffix,
            bytes memory userOpDomainsHashPrefix,
            bytes memory userOpDomainsHashSuffix,
            bytes memory cleanEcdsaSignature
        ) = abi.decode(
                _encodedSignature,
                (bytes32, bytes, bytes, bytes, bytes, bytes)
            );

        bytes32 userOpsRootHash = keccak256(
            abi.encodePacked(
                userOpsHashPrefix,
                hash(UserOperationHash({txHash: _userOpHash})),
                userOpsHashSuffix
            )
        );

        bytes32 userOpDomainsRootHash = keccak256(
            abi.encodePacked(
                userOpDomainsHashPrefix,
                hashChainDomain(),
                userOpDomainsHashSuffix
            )
        );

        bytes32 rootHashWithNonPrefix = keccak256(
            abi.encode(
                MULTI_TRANSACTION_TYPEHASH,
                novaTxsRootHash,
                userOpsRootHash,
                userOpDomainsRootHash
            )
        );

        bytes32 multiTransactionDomainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                MULTI_TRANSACTION_EIP712_DOMAIN_NAME,
                MULTI_TRANSACTION_EIP712_DOMAIN_VERSION,
                MULTI_TRANSACTION_EIP712_DOMAIN_CHAIN_ID
            )
        );
        rootHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                multiTransactionDomainSeparator,
                rootHashWithNonPrefix
            )
        );
        signature = cleanEcdsaSignature;
    }

    /**
     * @dev Checks if the address provided is a smart contract.
     * @param account Address to be checked.
     */
    function _isSmartContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    /**
     * @dev Returns the hash of the chain domain.
     * @return hash of the chain domain.
     */
    function hashChainDomain() internal view returns (bytes32) {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        return
            keccak256(
                abi.encode(
                    CHAIN_DOMAIN_TYPEHASH,
                    keccak256(bytes(NAME)),
                    keccak256(bytes(VERSION)),
                    chainId,
                    address(this)
                )
            );
    }

    /**
     * @dev Returns the hash of the user operation.
     * @param userOpHash Hash of the User Operation to be validated.
     * @return hash of the user operation.
     */
    function hash(
        UserOperationHash memory userOpHash
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(USER_OPERATION_HASH_TYPEHASH, userOpHash.txHash)
            );
    }
}
