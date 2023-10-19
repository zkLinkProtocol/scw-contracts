// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IStakeable} from "../interfaces/common/IStakeable.sol";

/**
 * @title Stakeable Entity
 * @author Fil Makarov - <filipp.makarov@biconomy.io>
 */
contract Stakeable is Ownable, IStakeable {
    constructor(address _newOwner) {
        _transferOwnership(_newOwner);
    }

    function addStake(
        address epAddress,
        uint32 unstakeDelaySec
    ) external payable override onlyOwner {
        require(epAddress != address(0), "Invalid EP address");
        IEntryPoint(epAddress).addStake{value: msg.value}(unstakeDelaySec);
    }

    function unlockStake(address epAddress) external override onlyOwner {
        require(epAddress != address(0), "Invalid EP address");
        IEntryPoint(epAddress).unlockStake();
    }

    function withdrawStake(
        address epAddress,
        address payable withdrawAddress
    ) external override onlyOwner {
        require(epAddress != address(0), "Invalid EP address");
        IEntryPoint(epAddress).withdrawStake(withdrawAddress);
    }
}
