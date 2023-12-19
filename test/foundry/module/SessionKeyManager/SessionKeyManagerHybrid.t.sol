// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {SATestBase, IEntryPoint} from "../../base/SATestBase.sol";
import {SmartAccount} from "sa/SmartAccount.sol";
import {UserOperation} from "aa-core/EntryPoint.sol";
import {SessionKeyManagerHybrid} from "sa/modules/SessionKeyManagers/SessionKeyManagerHybrid.sol";
import {IStatefulSessionKeyManagerBase} from "sa/interfaces/modules/SessionKeyManagers/IStatefulSessionKeyManagerBase.sol";
import {MockSessionValidationModule} from "sa/test/mocks/MockSessionValidationModule.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Vm} from "forge-std/Test.sol";

contract SessionKeyManagerHybridTest is SATestBase {
    SmartAccount private sa;
    SessionKeyManagerHybrid private sessionKeyManagerHybrid;
    MockSessionValidationModule private mockSessionValidationModule;
    Stub private stub = new Stub();

    // Events
    event SessionCreated(
        address indexed sa,
        bytes32 indexed sessionDataDigest,
        IStatefulSessionKeyManagerBase.SessionData data
    );
    event SessionDisabled(
        address indexed sa,
        bytes32 indexed sessionDataDigest
    );
    event Log(string message);

    function setUp() public virtual override {
        super.setUp();

        // Deploy Smart Account with default module
        uint256 smartAccountDeploymentIndex = 0;
        bytes memory moduleSetupData = getEcdsaOwnershipRegistryModuleSetupData(
            alice.addr
        );
        sa = getSmartAccountWithModule(
            address(ecdsaOwnershipRegistryModule),
            moduleSetupData,
            smartAccountDeploymentIndex,
            "aliceSA"
        );

        // Deploy Session Key Modules
        sessionKeyManagerHybrid = new SessionKeyManagerHybrid();
        vm.label(address(sessionKeyManagerHybrid), "sessionKeyManagerHybrid");
        mockSessionValidationModule = new MockSessionValidationModule();
        vm.label(
            address(mockSessionValidationModule),
            "mockSessionValidationModule"
        );

        // Enable Session Key Manager Module
        UserOperation memory op = makeEcdsaModuleUserOp(
            getSmartAccountExecuteCalldata(
                address(sa),
                0,
                abi.encodeCall(
                    sa.enableModule,
                    address(sessionKeyManagerHybrid)
                )
            ),
            sa,
            0,
            alice
        );
        entryPoint.handleOps(arraifyOps(op), owner.addr);
    }

    function testEnableAndUseSession() public {
        SessionKeyManagerHybrid.SessionData
            memory sessionData = IStatefulSessionKeyManagerBase.SessionData({
                validUntil: 0,
                validAfter: 0,
                sessionValidationModule: address(mockSessionValidationModule),
                sessionKeyData: abi.encodePacked(bob.addr)
            });
        bytes32 sessionDataDigest = sessionKeyManagerHybrid.sessionDataDigest(
            sessionData
        );

        // Generate Session Data
        uint64[] memory chainIds = new uint64[](1);
        chainIds[0] = uint64(block.chainid);

        SessionKeyManagerHybrid.SessionData[]
            memory sessionDatas = new SessionKeyManagerHybrid.SessionData[](1);
        sessionDatas[0] = sessionData;

        (
            bytes memory sessionEnableData,
            bytes memory sessionEnableSignature
        ) = makeSessionEnableData(chainIds, sessionDatas, sa);

        // Enable and Use session
        UserOperation memory op = makeEnableAndUseSessionUserOp(
            getSmartAccountExecuteCalldata(
                address(stub),
                0,
                abi.encodeCall(
                    stub.emitMessage,
                    ("shouldProcessTransactionFromSessionKey")
                )
            ),
            sa,
            0,
            sessionKeyManagerHybrid,
            sessionData,
            bob,
            0,
            sessionEnableData,
            sessionEnableSignature
        );

        vm.expectEmit();
        emit SessionCreated(address(sa), sessionDataDigest, sessionData);
        vm.expectEmit();
        emit Log("shouldProcessTransactionFromSessionKey");
        entryPoint.handleOps(arraifyOps(op), owner.addr);

        // Check session is enabled
        IStatefulSessionKeyManagerBase.SessionData
            memory enabledSessionData = sessionKeyManagerHybrid
                .enabledSessionsData(sessionDataDigest, address(sa));
        assertEq(enabledSessionData, sessionData);
    }

    function testEnableAndUseSessionPostCaching() public {
        SessionKeyManagerHybrid.SessionData
            memory sessionData = IStatefulSessionKeyManagerBase.SessionData({
                validUntil: 0,
                validAfter: 0,
                sessionValidationModule: address(mockSessionValidationModule),
                sessionKeyData: abi.encodePacked(bob.addr)
            });

        // Generate Session Data
        uint64[] memory chainIds = new uint64[](1);
        chainIds[0] = uint64(block.chainid);

        SessionKeyManagerHybrid.SessionData[]
            memory sessionDatas = new SessionKeyManagerHybrid.SessionData[](1);
        sessionDatas[0] = sessionData;

        (
            bytes memory sessionEnableData,
            bytes memory sessionEnableSignature
        ) = makeSessionEnableData(chainIds, sessionDatas, sa);

        // Enable and Use session for the first time
        UserOperation memory op = makeEnableAndUseSessionUserOp(
            getSmartAccountExecuteCalldata(
                address(stub),
                0,
                abi.encodeCall(
                    stub.emitMessage,
                    ("shouldProcessTransactionFromSessionKey")
                )
            ),
            sa,
            0,
            sessionKeyManagerHybrid,
            sessionData,
            bob,
            0,
            sessionEnableData,
            sessionEnableSignature
        );
        entryPoint.handleOps(arraifyOps(op), owner.addr);

        // Use session with just digest
        op = makeUseExistingSessionUserOp(
            getSmartAccountExecuteCalldata(
                address(stub),
                0,
                abi.encodeCall(
                    stub.emitMessage,
                    ("shouldProcessTransactionFromSessionKey")
                )
            ),
            sa,
            0,
            sessionKeyManagerHybrid,
            sessionData,
            bob
        );
        vm.expectEmit();
        emit Log("shouldProcessTransactionFromSessionKey");
        entryPoint.handleOps(arraifyOps(op), owner.addr);
    }

    function testEnableAndUseSessionMultiSessionEnable() public {
        // Generate Session Data
        uint64[] memory chainIds = new uint64[](5);
        SessionKeyManagerHybrid.SessionData[]
            memory sessionDatas = new SessionKeyManagerHybrid.SessionData[](5);

        for (uint256 i = 0; i < chainIds.length; ++i) {
            sessionDatas[i] = IStatefulSessionKeyManagerBase.SessionData({
                validUntil: uint48(block.timestamp + i),
                validAfter: uint48(block.timestamp),
                sessionValidationModule: address(mockSessionValidationModule),
                sessionKeyData: abi.encodePacked(bob.addr)
            });

            chainIds[i] = uint64(block.chainid);
        }

        (
            bytes memory sessionEnableData,
            bytes memory sessionEnableSignature
        ) = makeSessionEnableData(chainIds, sessionDatas, sa);

        // Enable and Use session
        UserOperation memory op = makeEnableAndUseSessionUserOp(
            getSmartAccountExecuteCalldata(
                address(stub),
                0,
                abi.encodeCall(
                    stub.emitMessage,
                    ("shouldProcessTransactionFromSessionKey")
                )
            ),
            sa,
            0,
            sessionKeyManagerHybrid,
            sessionDatas[0],
            bob,
            0,
            sessionEnableData,
            sessionEnableSignature
        );

        bytes32 sessionDataDigest = sessionKeyManagerHybrid.sessionDataDigest(
            sessionDatas[0]
        );

        vm.expectEmit();
        emit SessionCreated(address(sa), sessionDataDigest, sessionDatas[0]);
        vm.expectEmit();
        emit Log("shouldProcessTransactionFromSessionKey");
        entryPoint.handleOps(arraifyOps(op), owner.addr);

        // Check session is enabled
        IStatefulSessionKeyManagerBase.SessionData
            memory enabledSessionData = sessionKeyManagerHybrid
                .enabledSessionsData(sessionDataDigest, address(sa));
        assertEq(enabledSessionData, sessionDatas[0]);

        // Ensure other sessions are not enabled
        for (uint256 i = 1; i < sessionDatas.length; ++i) {
            enabledSessionData = sessionKeyManagerHybrid.enabledSessionsData(
                sessionKeyManagerHybrid.sessionDataDigest(sessionDatas[i]),
                address(sa)
            );
            IStatefulSessionKeyManagerBase.SessionData memory emptyData;
            assertEq(enabledSessionData, emptyData);
        }
    }

    function testDisableSession() public {
        SessionKeyManagerHybrid.SessionData
            memory sessionData = IStatefulSessionKeyManagerBase.SessionData({
                validUntil: 0,
                validAfter: 0,
                sessionValidationModule: address(mockSessionValidationModule),
                sessionKeyData: abi.encodePacked(bob.addr)
            });
        bytes32 sessionDataDigest = sessionKeyManagerHybrid.sessionDataDigest(
            sessionData
        );

        // Generate Session Data
        uint64[] memory chainIds = new uint64[](1);
        chainIds[0] = uint64(block.chainid);

        SessionKeyManagerHybrid.SessionData[]
            memory sessionDatas = new SessionKeyManagerHybrid.SessionData[](1);
        sessionDatas[0] = sessionData;

        (
            bytes memory sessionEnableData,
            bytes memory sessionEnableSignature
        ) = makeSessionEnableData(chainIds, sessionDatas, sa);

        // Enable and Use session
        UserOperation memory op = makeEnableAndUseSessionUserOp(
            getSmartAccountExecuteCalldata(
                address(stub),
                0,
                abi.encodeCall(
                    stub.emitMessage,
                    ("shouldProcessTransactionFromSessionKey")
                )
            ),
            sa,
            0,
            sessionKeyManagerHybrid,
            sessionData,
            bob,
            0,
            sessionEnableData,
            sessionEnableSignature
        );
        entryPoint.handleOps(arraifyOps(op), owner.addr);

        // Disable session
        op = makeEcdsaModuleUserOp(
            getSmartAccountExecuteCalldata(
                address(sessionKeyManagerHybrid),
                0,
                abi.encodeCall(
                    sessionKeyManagerHybrid.disableSession,
                    (sessionDataDigest)
                )
            ),
            sa,
            0,
            alice
        );
        vm.expectEmit();
        emit SessionDisabled(address(sa), sessionDataDigest);

        entryPoint.handleOps(arraifyOps(op), owner.addr);

        // Check session is disabled
        IStatefulSessionKeyManagerBase.SessionData
            memory enabledSessionData = sessionKeyManagerHybrid
                .enabledSessionsData(sessionDataDigest, address(sa));

        IStatefulSessionKeyManagerBase.SessionData memory emptyData;
        assertEq(enabledSessionData, emptyData);
    }

    function testShouldNotValidateTransactionFromNonEnabledSession() public {
        // Generate Session Data
        uint64[] memory chainIds = new uint64[](5);
        SessionKeyManagerHybrid.SessionData[]
            memory sessionDatas = new SessionKeyManagerHybrid.SessionData[](5);

        for (uint256 i = 0; i < chainIds.length; ++i) {
            sessionDatas[i] = IStatefulSessionKeyManagerBase.SessionData({
                validUntil: uint48(block.timestamp + i),
                validAfter: uint48(block.timestamp),
                sessionValidationModule: address(mockSessionValidationModule),
                sessionKeyData: abi.encodePacked(bob.addr)
            });

            chainIds[i] = uint64(block.chainid);
        }

        (
            bytes memory sessionEnableData,
            bytes memory sessionEnableSignature
        ) = makeSessionEnableData(chainIds, sessionDatas, sa);

        // Use session not in session enable data
        sessionDatas[0].validUntil *= 2;
        UserOperation memory op = makeEnableAndUseSessionUserOp(
            getSmartAccountExecuteCalldata(
                address(stub),
                0,
                abi.encodeCall(
                    stub.emitMessage,
                    ("shouldProcessTransactionFromSessionKey")
                )
            ),
            sa,
            0,
            sessionKeyManagerHybrid,
            sessionDatas[0],
            bob,
            0,
            sessionEnableData,
            sessionEnableSignature
        );

        try entryPoint.handleOps(arraifyOps(op), owner.addr) {
            fail("should have reverted");
        } catch (bytes memory reason) {
            assertEq(
                reason,
                abi.encodeWithSelector(
                    IEntryPoint.FailedOp.selector,
                    0,
                    "AA23 reverted: SessionKeyDataHashMismatch"
                )
            );
        }
    }

    function testShouldNotValidateTransactionFromNonEnabledSessionWithPostCacheFlow()
        public
    {
        SessionKeyManagerHybrid.SessionData
            memory sessionData = IStatefulSessionKeyManagerBase.SessionData({
                validUntil: 0,
                validAfter: 0,
                sessionValidationModule: address(mockSessionValidationModule),
                sessionKeyData: abi.encodePacked(bob.addr)
            });

        // Do not enable session

        // Use session
        UserOperation memory op = makeUseExistingSessionUserOp(
            getSmartAccountExecuteCalldata(
                address(stub),
                0,
                abi.encodeCall(
                    stub.emitMessage,
                    ("shouldProcessTransactionFromSessionKey")
                )
            ),
            sa,
            0,
            sessionKeyManagerHybrid,
            sessionData,
            bob
        );

        try entryPoint.handleOps(arraifyOps(op), owner.addr) {
            fail("should have reverted");
        } catch (bytes memory reason) {
            assertEq(
                reason,
                abi.encodeWithSelector(
                    IEntryPoint.FailedOp.selector,
                    0,
                    "AA23 reverted: SKM: Session key is not enabled"
                )
            );
        }
    }

    function testShouldNotValidateTransactionSignedFromInvalidSessionSigner()
        public
    {
        SessionKeyManagerHybrid.SessionData
            memory sessionData = IStatefulSessionKeyManagerBase.SessionData({
                validUntil: 0,
                validAfter: 0,
                sessionValidationModule: address(mockSessionValidationModule),
                sessionKeyData: abi.encodePacked(bob.addr)
            });

        // Generate Session Data
        uint64[] memory chainIds = new uint64[](1);
        chainIds[0] = uint64(block.chainid);

        SessionKeyManagerHybrid.SessionData[]
            memory sessionDatas = new SessionKeyManagerHybrid.SessionData[](1);
        sessionDatas[0] = sessionData;

        (
            bytes memory sessionEnableData,
            bytes memory sessionEnableSignature
        ) = makeSessionEnableData(chainIds, sessionDatas, sa);

        // Enable and Use session
        UserOperation memory op = makeEnableAndUseSessionUserOp(
            getSmartAccountExecuteCalldata(
                address(stub),
                0,
                abi.encodeCall(
                    stub.emitMessage,
                    ("shouldProcessTransactionFromSessionKey")
                )
            ),
            sa,
            0,
            sessionKeyManagerHybrid,
            sessionData,
            charlie,
            0,
            sessionEnableData,
            sessionEnableSignature
        );
        try entryPoint.handleOps(arraifyOps(op), owner.addr) {
            fail("should have reverted");
        } catch (bytes memory reason) {
            assertEq(
                reason,
                abi.encodeWithSelector(
                    IEntryPoint.FailedOp.selector,
                    0,
                    "AA24 signature error"
                )
            );
        }
    }

    function testShouldNotValidateTransactionWithInvalidSessionIndex() public {
        SessionKeyManagerHybrid.SessionData
            memory sessionData = IStatefulSessionKeyManagerBase.SessionData({
                validUntil: 0,
                validAfter: 0,
                sessionValidationModule: address(mockSessionValidationModule),
                sessionKeyData: abi.encodePacked(bob.addr)
            });

        // Generate Session Data
        uint64[] memory chainIds = new uint64[](1);
        chainIds[0] = uint64(block.chainid);

        SessionKeyManagerHybrid.SessionData[]
            memory sessionDatas = new SessionKeyManagerHybrid.SessionData[](1);
        sessionDatas[0] = sessionData;

        (
            bytes memory sessionEnableData,
            bytes memory sessionEnableSignature
        ) = makeSessionEnableData(chainIds, sessionDatas, sa);

        // Enable and Use session
        UserOperation memory op = makeEnableAndUseSessionUserOp(
            getSmartAccountExecuteCalldata(
                address(stub),
                0,
                abi.encodeCall(
                    stub.emitMessage,
                    ("shouldProcessTransactionFromSessionKey")
                )
            ),
            sa,
            0,
            sessionKeyManagerHybrid,
            sessionData,
            bob,
            chainIds.length,
            sessionEnableData,
            sessionEnableSignature
        );
        try entryPoint.handleOps(arraifyOps(op), owner.addr) {
            fail("should have reverted");
        } catch (bytes memory reason) {
            assertEq(
                reason,
                abi.encodeWithSelector(
                    IEntryPoint.FailedOp.selector,
                    0,
                    "AA23 reverted: SessionKeyIndexInvalid"
                )
            );
        }
    }

    function testShouldNotValidateTransactionWithInvalidChainId() public {
        SessionKeyManagerHybrid.SessionData
            memory sessionData = IStatefulSessionKeyManagerBase.SessionData({
                validUntil: 0,
                validAfter: 0,
                sessionValidationModule: address(mockSessionValidationModule),
                sessionKeyData: abi.encodePacked(bob.addr)
            });

        // Generate Session Data
        uint64[] memory chainIds = new uint64[](1);
        chainIds[0] = uint64(block.chainid);
        chainIds[0] += 1;

        SessionKeyManagerHybrid.SessionData[]
            memory sessionDatas = new SessionKeyManagerHybrid.SessionData[](1);
        sessionDatas[0] = sessionData;

        (
            bytes memory sessionEnableData,
            bytes memory sessionEnableSignature
        ) = makeSessionEnableData(chainIds, sessionDatas, sa);

        // Enable and Use session
        UserOperation memory op = makeEnableAndUseSessionUserOp(
            getSmartAccountExecuteCalldata(
                address(stub),
                0,
                abi.encodeCall(
                    stub.emitMessage,
                    ("shouldProcessTransactionFromSessionKey")
                )
            ),
            sa,
            0,
            sessionKeyManagerHybrid,
            sessionData,
            bob,
            0,
            sessionEnableData,
            sessionEnableSignature
        );
        try entryPoint.handleOps(arraifyOps(op), owner.addr) {
            fail("should have reverted");
        } catch (bytes memory reason) {
            assertEq(
                reason,
                abi.encodeWithSelector(
                    IEntryPoint.FailedOp.selector,
                    0,
                    "AA23 reverted: SessionChainIdMismatch"
                )
            );
        }
    }

    function testShouldNotValidateTransactionSignedFromInvalidSessionSignerPostCaching()
        public
    {
        SessionKeyManagerHybrid.SessionData
            memory sessionData = IStatefulSessionKeyManagerBase.SessionData({
                validUntil: 0,
                validAfter: 0,
                sessionValidationModule: address(mockSessionValidationModule),
                sessionKeyData: abi.encodePacked(bob.addr)
            });

        // Generate Session Data
        uint64[] memory chainIds = new uint64[](1);
        chainIds[0] = uint64(block.chainid);

        SessionKeyManagerHybrid.SessionData[]
            memory sessionDatas = new SessionKeyManagerHybrid.SessionData[](1);
        sessionDatas[0] = sessionData;

        (
            bytes memory sessionEnableData,
            bytes memory sessionEnableSignature
        ) = makeSessionEnableData(chainIds, sessionDatas, sa);

        // Enable and Use session
        UserOperation memory op = makeEnableAndUseSessionUserOp(
            getSmartAccountExecuteCalldata(
                address(stub),
                0,
                abi.encodeCall(
                    stub.emitMessage,
                    ("shouldProcessTransactionFromSessionKey")
                )
            ),
            sa,
            0,
            sessionKeyManagerHybrid,
            sessionData,
            bob,
            0,
            sessionEnableData,
            sessionEnableSignature
        );
        entryPoint.handleOps(arraifyOps(op), owner.addr);

        // Use session with just digest but wrong signer
        op = makeUseExistingSessionUserOp(
            getSmartAccountExecuteCalldata(
                address(stub),
                0,
                abi.encodeCall(
                    stub.emitMessage,
                    ("shouldProcessTransactionFromSessionKey")
                )
            ),
            sa,
            0,
            sessionKeyManagerHybrid,
            sessionData,
            charlie
        );
        try entryPoint.handleOps(arraifyOps(op), owner.addr) {
            fail("should have reverted");
        } catch (bytes memory reason) {
            assertEq(
                reason,
                abi.encodeWithSelector(
                    IEntryPoint.FailedOp.selector,
                    0,
                    "AA24 signature error"
                )
            );
        }
    }

    function testShouldNotSupportERC1271SignatureValidation(
        uint256 seed
    ) public {
        bytes32 userOpHash = keccak256(abi.encodePacked(seed));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice.privateKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        assertEq(
            sessionKeyManagerHybrid.isValidSignature(userOpHash, signature),
            bytes4(0xffffffff)
        );
    }

    function testShouldNotSupportERC1271SignatureValidationUnsafe(
        uint256 seed
    ) public {
        bytes32 userOpHash = keccak256(abi.encodePacked(seed));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice.privateKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        assertEq(
            sessionKeyManagerHybrid.isValidSignatureUnsafe(
                userOpHash,
                signature
            ),
            bytes4(0xffffffff)
        );
    }

    function assertEq(
        SessionKeyManagerHybrid.SessionData memory _a,
        SessionKeyManagerHybrid.SessionData memory _b
    ) internal {
        assertEq(_a.validUntil, _b.validUntil, "mismatched validUntil");
        assertEq(_a.validAfter, _b.validAfter, "mismatched validAfter");
        assertEq(
            _a.sessionValidationModule,
            _b.sessionValidationModule,
            "mismatched sessionValidationModule"
        );
        assertEq(
            _a.sessionKeyData,
            _b.sessionKeyData,
            "mismatched sessionKeyData"
        );
    }

    function makeSessionEnableData(
        uint64[] memory chainIds,
        SessionKeyManagerHybrid.SessionData[] memory _sessionDatas,
        SmartAccount _signer
    ) internal view returns (bytes memory, bytes memory) {
        bytes32[] memory sessionDigests = new bytes32[](_sessionDatas.length);
        for (uint256 i = 0; i < _sessionDatas.length; i++) {
            sessionDigests[i] = sessionKeyManagerHybrid.sessionDataDigest(
                _sessionDatas[i]
            );
        }
        bytes memory sessionEnableData = abi.encodePacked(
            uint8(_sessionDatas.length)
        );
        for (uint256 i = 0; i < chainIds.length; ++i) {
            sessionEnableData = abi.encodePacked(
                sessionEnableData,
                chainIds[i]
            );
        }
        sessionEnableData = abi.encodePacked(sessionEnableData, sessionDigests);

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n52",
                keccak256(sessionEnableData),
                _signer
            )
        );
        TestAccount memory owner = testAccountsByAddress[
            ecdsaOwnershipRegistryModule.getOwner(address(_signer))
        ];
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.privateKey, digest);
        bytes memory erc1271Signature = abi.encode(
            abi.encodePacked(r, s, v),
            ecdsaOwnershipRegistryModule
        );
        return (sessionEnableData, erc1271Signature);
    }

    function makeEnableAndUseSessionUserOp(
        bytes memory _calldata,
        SmartAccount _sa,
        uint192 _nonceKey,
        SessionKeyManagerHybrid _skm,
        SessionKeyManagerHybrid.SessionData memory _sessionData,
        TestAccount memory _sessionSigner,
        uint256 _sessionKeyIndex,
        bytes memory _sessionEnableData,
        bytes memory _sessionEnableSignature
    ) internal view returns (UserOperation memory op) {
        op = UserOperation({
            sender: address(_sa),
            nonce: entryPoint.getNonce(address(_sa), _nonceKey),
            initCode: bytes(""),
            callData: _calldata,
            callGasLimit: gasleft() / 100,
            verificationGasLimit: gasleft() / 100,
            preVerificationGas: defaultPreVerificationGas,
            maxFeePerGas: tx.gasprice,
            maxPriorityFeePerGas: tx.gasprice - block.basefee,
            paymasterAndData: bytes(""),
            signature: bytes("")
        });

        bytes memory sessionKeySignature;
        {
            // Sign the UserOp
            bytes32 userOpHash = entryPoint.getUserOpHash(op);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                _sessionSigner.privateKey,
                ECDSA.toEthSignedMessageHash(userOpHash)
            );
            sessionKeySignature = abi.encodePacked(r, s, v);
        }

        // Generate Module Signature
        bytes memory moduleSignature = abi.encodePacked(
            uint8(0x01),
            uint8(_sessionKeyIndex),
            _sessionData.validUntil,
            _sessionData.validAfter,
            _sessionData.sessionValidationModule,
            abi.encode(
                _sessionData.sessionKeyData,
                _sessionEnableData,
                _sessionEnableSignature,
                sessionKeySignature
            )
        );
        op.signature = abi.encode(moduleSignature, _skm);
    }

    function makeUseExistingSessionUserOp(
        bytes memory _calldata,
        SmartAccount _sa,
        uint192 _nonceKey,
        SessionKeyManagerHybrid _skm,
        SessionKeyManagerHybrid.SessionData memory _sessionData,
        TestAccount memory _sessionSigner
    ) internal view returns (UserOperation memory op) {
        op = UserOperation({
            sender: address(_sa),
            nonce: entryPoint.getNonce(address(_sa), _nonceKey),
            initCode: bytes(""),
            callData: _calldata,
            callGasLimit: gasleft() / 100,
            verificationGasLimit: gasleft() / 100,
            preVerificationGas: defaultPreVerificationGas,
            maxFeePerGas: tx.gasprice,
            maxPriorityFeePerGas: tx.gasprice - block.basefee,
            paymasterAndData: bytes(""),
            signature: bytes("")
        });

        // Sign the UserOp
        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _sessionSigner.privateKey,
            ECDSA.toEthSignedMessageHash(userOpHash)
        );
        bytes memory sessionKeySignature = abi.encodePacked(r, s, v);

        // Generate Module Signature
        bytes memory moduleSignature = abi.encodePacked(
            uint8(0x00),
            abi.encode(
                sessionKeyManagerHybrid.sessionDataDigest(_sessionData),
                sessionKeySignature
            )
        );
        op.signature = abi.encode(moduleSignature, _skm);
    }
}

contract Stub {
    event Log(string message);

    function emitMessage(string calldata _message) public {
        emit Log(_message);
    }
}
