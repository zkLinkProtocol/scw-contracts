// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.17;

/* solhint-disable reason-string */

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IPaymaster} from "@vechain/account-abstraction-contracts/interfaces/IPaymaster.sol";
import {IEntryPoint} from "@vechain/account-abstraction-contracts/interfaces/IEntryPoint.sol";
import {UserOperation} from "@vechain/account-abstraction-contracts/interfaces/UserOperation.sol";
import {BaseSmartAccountErrors} from "../common/Errors.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
/**
 * Helper class for creating a paymaster.
 * provides helper methods for staking.
 * validates that the postOp is called only by the entryPoint
 */
// @notice Could have Ownable2Step
abstract contract BasePaymaster is IPaymaster, Ownable, BaseSmartAccountErrors {
    // VTHO Token Information
    address public constant VTHO_TOKEN_ADDRESS = 0x0000000000000000000000000000456E65726779;
    IERC20 public constant VTHO_TOKEN_CONTRACT = IERC20(VTHO_TOKEN_ADDRESS);

    IEntryPoint public immutable entryPoint;

    constructor(address _owner, IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        _transferOwnership(_owner);
    }

    /**
     * add a deposit for this paymaster, used for paying for transaction fees
     */
    function deposit() external virtual;

    /// @inheritdoc IPaymaster
    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) external override {
        _requireFromEntryPoint();
        _postOp(mode, context, actualGasCost);
    }

    /// @inheritdoc IPaymaster
    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external
        override
        returns (bytes memory context, uint256 validationData)
    {
        _requireFromEntryPoint();
        return _validatePaymasterUserOp(userOp, userOpHash, maxCost);
    }

    /**
     * withdraw value from the deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawTo(address withdrawAddress, uint256 amount) external virtual;

    /**
     * add stake for this paymaster.
     * @param unstakeDelaySec - the unstake delay for this paymaster. Can only be increased.
     * @param amount amount of VTHO to stake
     */
    function addStake(uint32 unstakeDelaySec, uint256 amount) external onlyOwner {
        require(VTHO_TOKEN_CONTRACT.transferFrom(msg.sender, address(this), amount), "Paymaster stake transfer failed");
        require(VTHO_TOKEN_CONTRACT.approve(address(entryPoint), amount), "Paymaster stake approval failed");
        entryPoint.addStakeAmount(unstakeDelaySec, amount);
    }

    /**
     * unlock the stake, in order to withdraw it.
     * The paymaster can't serve requests once unlocked, until it calls addStake again
     */
    function unlockStake() external onlyOwner {
        entryPoint.unlockStake();
    }

    /**
     * withdraw the entire paymaster's stake.
     * stake must be unlocked first (and then wait for the unstakeDelay to be over)
     * @param withdrawAddress the address to send withdrawn value.
     */
    function withdrawStake(address withdrawAddress) external onlyOwner {
        entryPoint.withdrawStake(withdrawAddress);
    }

    /**
     * return current paymaster's deposit on the entryPoint.
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    function _validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        internal
        virtual
        returns (bytes memory context, uint256 validationData);

    /**
     * post-operation handler.
     * (verified to be called only through the entryPoint)
     * @dev if subclass returns a non-empty context from validatePaymasterUserOp, it must also implement this method.
     * @param mode enum with the following options:
     *      opSucceeded - user operation succeeded.
     *      opReverted  - user op reverted. still has to pay for gas.
     *      postOpReverted - user op succeeded, but caused postOp (in mode=opSucceeded) to revert.
     *                       Now this is the 2nd call, after user's op was deliberately reverted.
     * @param context - the context value returned by validatePaymasterUserOp
     * @param actualGasCost - actual gas used so far (without this postOp call).
     */
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) internal virtual {
        (mode, context, actualGasCost); // unused params
        // subclass must override this method if validatePaymasterUserOp returns a context
        revert("must override");
    }

    /// validate the call is made from a valid entrypoint
    function _requireFromEntryPoint() internal virtual {
        // require(msg.sender == address(entryPoint), "Sender not EntryPoint"); // won't need BaseSmartAccountErrors import
        if (msg.sender != address(entryPoint)) {
            revert CallerIsNotAnEntryPoint(msg.sender);
        }
    }
}