// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.8.17 <0.9.0;

import "./Topology.sol";

/**
 * @title Decoder - a library that discovers parameter locations in calldata
 * from a list of conditions.
 * @author Cristóvão Honorato - <cristovao.honorato@gnosis.io>
 */
library Decoder {
    /**
     * @dev Maps the location and size of parameters in the encoded transaction data.
     * @param data The encoded transaction data.
     * @param condition The condition of the parameters.
     * @return result The mapped location and size of parameters in the encoded transaction data.
     */
    function inspect(
        bytes calldata data,
        Condition memory condition
    ) internal pure returns (ParameterPayload memory result) {
        /*
         * In the parameter encoding area, there is a region called the head
         * that is divided into 32-byte chunks. Each parameter has its own
         * corresponding chunk in the head region:
         * - Static parameters are encoded inline.
         * - Dynamic parameters have an offset to the tail, which is the start
         *   of the actual encoding for the dynamic parameter. Note that the
         *   offset does not include the 4-byte function signature."
         *
         */
        Topology.TypeTree memory typeNode = Topology.typeTree(condition);
        result = __block__(data, 4, typeNode, typeNode.children.length, false);
        result.location = 0;
        result.size = data.length;
    }

    /**
     * @dev Walks through a parameter encoding tree and maps their location and
     * size within calldata.
     * @param data The encoded transaction data.
     * @param location The current offset within the calldata buffer.
     * @param typeNode The current node being traversed within the parameter tree.
     * @return result The location and size of the parameter within calldata.
     */
    function _walk(
        bytes calldata data,
        uint256 location,
        Topology.TypeTree memory typeNode
    ) private pure returns (ParameterPayload memory result) {
        ParameterType paramType = typeNode.paramType;

        if (paramType == ParameterType.Static) {
            result.size = 32;
        } else if (paramType == ParameterType.Dynamic) {
            result.size = 32 + _ceil32(uint256(word(data, location)));
        } else if (paramType == ParameterType.Tuple) {
            result = __block__(
                data,
                location,
                typeNode,
                typeNode.children.length,
                false
            );
        } else if (paramType == ParameterType.Array) {
            result = __block__(
                data,
                location + 32,
                typeNode,
                uint256(word(data, location)),
                true
            );
            result.size += 32;
        } else if (paramType == ParameterType.AbiEncoded) {
            result = __block__(
                data,
                location + 32 + 4,
                typeNode,
                typeNode.children.length,
                false
            );
            result.size = 32 + _ceil32(uint256(word(data, location)));
        }
        result.location = location;
    }

    /**
     * @dev Recursively walk through the TypeTree to decode a block of parameters.
     * @param data The encoded transaction data.
     * @param location The current location of the parameter block being processed.
     * @param typeNode The current TypeTree node being processed.
     * @param length The number of parts in the block.
     * @param templateChild whether first child is type descriptor for all parts.
     * @return result The decoded ParameterPayload.
     */
    function __block__(
        bytes calldata data,
        uint256 location,
        Topology.TypeTree memory typeNode,
        uint256 length,
        bool templateChild
    ) private pure returns (ParameterPayload memory result) {
        result.children = new ParameterPayload[](length);

        bool isInline;
        if (templateChild) {
            isInline = Topology.isInline(typeNode.children[0]);
        }

        unchecked {
            uint256 offset;
            for (uint256 i; i < length; i++) {
                if (!templateChild) {
                    isInline = Topology.isInline(typeNode.children[i]);
                }

                result.children[i] = _walk(
                    data,
                    _locationInBlock(data, location, offset, isInline),
                    typeNode.children[templateChild ? 0 : i]
                );
                result.size += result.children[i].size + (isInline ? 0 : 32);
                offset += isInline ? result.children[i].size : 32;
            }
        }
    }

    /**
     * @dev Returns the location of a block part, which may be located inline
     * within the block - at the HEAD - or at an offset relative to the start
     * of the block - at the TAIL.
     *
     * @param data The encoded transaction data.
     * @param location The location of the block within the calldata buffer.
     * @param offset The offset of the block part, relative to the start of the block.
     * @param isInline Whether the block part is located inline within the block.
     *
     * @return The location of the block part within the calldata buffer.
     */
    function _locationInBlock(
        bytes calldata data,
        uint256 location,
        uint256 offset,
        bool isInline
    ) private pure returns (uint256) {
        uint256 headLocation = location + offset;
        if (isInline) {
            return headLocation;
        } else {
            return location + uint256(word(data, headLocation));
        }
    }

    /**
     * @dev Plucks a slice of bytes from calldata.
     * @param data The calldata to pluck the slice from.
     * @param location The starting location of the slice.
     * @param size The size of the slice.
     * @return A slice of bytes from calldata.
     */
    function pluck(
        bytes calldata data,
        uint256 location,
        uint256 size
    ) internal pure returns (bytes calldata) {
        return data[location:location + size];
    }

    /**
     * @dev Loads a word from calldata.
     * @param data The calldata to load the word from.
     * @param location The starting location of the slice.
     * @return result 32 byte word from calldata.
     */
    function word(
        bytes calldata data,
        uint256 location
    ) internal pure returns (bytes32 result) {
        assembly {
            result := calldataload(add(data.offset, location))
        }
    }

    function _ceil32(uint256 size) private pure returns (uint256) {
        // pad size. Source: http://www.cs.nott.ac.uk/~psarb2/G51MPC/slides/NumberLogic.pdf
        return ((size + 32 - 1) / 32) * 32;
    }
}
