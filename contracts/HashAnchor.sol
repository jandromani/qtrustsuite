// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract HashAnchor {
    event HashStored(string _hash, string _data, address indexed sender);

    function storeHash(string calldata _hash, string calldata _data) external {
        emit HashStored(_hash, _data, msg.sender);
    }
}
