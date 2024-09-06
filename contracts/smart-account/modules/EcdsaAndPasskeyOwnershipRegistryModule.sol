// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {BaseAuthorizationModule} from "./BaseAuthorizationModule.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title ECDSA ownership Authorization module for Biconomy Smart Accounts.
 * @dev Compatible with Biconomy Modular Interface v 0.1
 *         - It allows to validate user operations signed by EOA private key.
 *         - EIP-1271 compatible (ensures Smart Account can validate signed messages).
 *         - One owner per Smart Account.
 *         - Does not support outdated eth_sign flow for cheaper validations
 *         (see https://support.metamask.io/hc/en-us/articles/14764161421467-What-is-eth-sign-and-why-is-it-a-risk-)
 * !!!!!!! Only EOA owners supported, no Smart Account Owners
 *         For Smart Contract Owners check SmartContractOwnership module instead
 * @author Fil Makarov - <filipp.makarov@biconomy.io>
 */

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

    error NoOwnerRegisteredForSmartAccount(address smartAccount);
    error NoTurnkeyWalletRegisteredForSmartAccount(address smartAccount);
    error NoRequiredSignerRegisteredForSmartAccount(address smartAccount);
    error AlreadyInitedForSmartAccount(address smartAccount);
    error WrongSignatureLength();
    error NotEOA(address account);
    error ZeroAddressNotAllowedAsOwner();
    error ZeroAddressNotAllowedAsTurnkeyWallet();

    constructor(uint256 _chainId) {
        // Set the chain ID for the EIP-712 domain.
        MULTI_TRANSACTION_EIP712_DOMAIN_CHAIN_ID = _chainId;
    }

    /**
     * @dev Initializes the module for a Smart Account.
     * Should be used at a time of first enabling the module for a Smart Account.
     * @param eoaOwner The owner of the Smart Account. Should be EOA!
     * @param turnkeyWallet The turnkey wallet of the Smart Account. Should be EOA!
     */
    function initForSmartAccount(
        address eoaOwner,
        address turnkeyWallet
    ) external returns (address) {
        if (_smartAccountOwners[msg.sender] != address(0))
            revert AlreadyInitedForSmartAccount(msg.sender);
        if (eoaOwner == address(0)) revert ZeroAddressNotAllowedAsOwner();
        if (turnkeyWallet == address(0))
            revert ZeroAddressNotAllowedAsTurnkeyWallet();
        _smartAccountOwners[msg.sender] = eoaOwner;
        _smartAccountTurnkey[msg.sender] = turnkeyWallet;
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
        if (turnkeyWallet == address(0)) revert ZeroAddressNotAllowedAsOwner();
        _transferTurnkeyWallet(msg.sender, turnkeyWallet);
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
     * @dev validates userOperation
     * @param userOp User Operation to be validated.
     * @param userOpHash Hash of the User Operation to be validated.
     * @return sigValidationResult 0 if signature is valid, SIG_VALIDATION_FAILED otherwise.
     */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) external view virtual returns (uint256) {
        bytes memory cleanEcdsaSignature;
        bytes32 rootHash;

        (bytes memory signature, ) = abi.decode(
            userOp.signature,
            (bytes, address)
        );
        cleanEcdsaSignature = signature;
        rootHash = userOpHash;

        if (signature.length > 65) {
            (
                bytes32 novaTxsRootHash,
                bytes memory userOpsHashPrefix,
                bytes memory userOpsHashSuffix,
                bytes memory userOpDomainsHashPrefix,
                bytes memory userOpDomainsHashSuffix,
                bytes memory tempCleanEcdsaSignature
            ) = abi.decode(
                    signature,
                    (bytes32, bytes, bytes, bytes, bytes, bytes)
                );

            bytes32 userOpsRootHash = keccak256(
                abi.encodePacked(
                    userOpsHashPrefix,
                    hash(UserOperationHash({txHash: userOpHash})),
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
            cleanEcdsaSignature = tempCleanEcdsaSignature;
        }

        if (_verifySignature(rootHash, cleanEcdsaSignature, userOp.sender)) {
            return VALIDATION_SUCCESS;
        }
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
        if (_verifySignature(dataHash, moduleSignature, smartAccount)) {
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
     * @dev Validates a signature for a message.
     * @dev Check if signature was made over dataHash.toEthSignedMessageHash() or just dataHash
     * The former is for personal_sign, the latter for the typed_data sign
     * Only EOA owners supported, no Smart Account Owners
     * For Smart Contract Owners check SmartContractOwnership Module instead
     * @param dataHash Hash of the data to be validated.
     * @param signature Signature to be validated.
     * @param smartAccount expected signer Smart Account address.
     * @return true if signature is valid, false otherwise.
     */
    function _verifySignature(
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
