// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.8.17 <0.9.0;

import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";

import "./Consumptions.sol";
import "./Core.sol";
import "./Decoder.sol";
import "./Periphery.sol";

import "./packers/BufferPacker.sol";

/**
 * @title PermissionChecker - a component of Zodiac Roles Mod responsible
 * for enforcing and authorizing actions performed on behalf of a role.
 *
 * @author Cristóvão Honorato - <cristovao.honorato@gnosis.io>
 * @author Jan-Felix Schwarz  - <jan-felix.schwarz@gnosis.io>
 */
abstract contract PermissionChecker is Core, Periphery {
    function _authorize(
        bytes32 roleKey,
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation
    ) internal view returns (Consumption[] memory) {
        // We never authorize the zero role, as it could clash with the
        // unassigned default role
        if (roleKey == 0) {
            revert NoMembership();
        }

        Role storage role = roles[roleKey];
        if (!role.members[msg.sender]) {
            revert NoMembership();
        }

        ITransactionUnwrapper adapter = getTransactionUnwrapper(
            to,
            bytes4(data)
        );

        Status status;
        Result memory result;
        if (address(adapter) == address(0)) {
            status = _transaction(role, to, value, data, operation, result);
        } else {
            status = _multiEntrypoint(
                ITransactionUnwrapper(adapter),
                role,
                to,
                value,
                data,
                operation,
                result
            );
        }
        if (status != Status.Ok) {
            revert ConditionViolation(status, result.info);
        }

        return result.consumptions;
    }

    function _multiEntrypoint(
        ITransactionUnwrapper adapter,
        Role storage role,
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        Result memory result
    ) private view returns (Status status) {
        try adapter.unwrap(to, value, data, operation) returns (
            UnwrappedTransaction[] memory transactions
        ) {
            unchecked {
                for (uint256 i; i < transactions.length; ++i) {
                    UnwrappedTransaction memory transaction = transactions[i];
                    uint256 left = transaction.dataLocation;
                    uint256 right = left + transaction.dataSize;
                    status = _transaction(
                        role,
                        transaction.to,
                        transaction.value,
                        data[left:right],
                        transaction.operation,
                        result
                    );
                    if (status != Status.Ok) {
                        return status;
                    }
                }
            }
        } catch {
            revert MalformedMultiEntrypoint();
        }
    }

    /// @dev Inspects an individual transaction and performs checks based on permission scoping.
    /// Wildcarded indicates whether params need to be inspected or not. When true, only ExecutionOptions are checked.
    /// @param role Role to check for.
    /// @param to Destination address of transaction.
    /// @param value Ether value of module transaction.
    /// @param data Data payload of module transaction.
    /// @param operation Operation type of module transaction: 0 == call, 1 == delegate call.
    function _transaction(
        Role storage role,
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        Result memory result
    ) private view returns (Status) {
        if (data.length != 0 && data.length < 4) {
            revert FunctionSignatureTooShort();
        }

        TargetAddress storage target = role.targets[to];
        if (target.clearance == Clearance.Target) {
            return _executionOptions(value, operation, target.options);
        } else if (target.clearance == Clearance.Function) {
            bytes32 key = _key(to, bytes4(data));
            bytes32 header = role.scopeConfig[key];
            if (header == 0) {
                result.info = bytes32(bytes4(data));
                return Status.FunctionNotAllowed;
            }

            (bool isWildcarded, ExecutionOptions options) = BufferPacker
                .unpackOptions(header);

            Status status = _executionOptions(value, operation, options);
            if (status != Status.Ok) {
                return status;
            }

            if (isWildcarded) {
                return Status.Ok;
            }

            return _scopedFunction(role, key, value, data, result);
        } else {
            return Status.TargetAddressNotAllowed;
        }
    }

    /// @dev Examines the ether value and operation for a given role target.
    /// @param value Ether value of module transaction.
    /// @param operation Operation type of module transaction: 0 == call, 1 == delegate call.
    /// @param options Determines if a transaction can send ether and/or delegatecall to target.
    function _executionOptions(
        uint256 value,
        Enum.Operation operation,
        ExecutionOptions options
    ) private pure returns (Status) {
        // isSend && !canSend
        if (
            value > 0 &&
            options != ExecutionOptions.Send &&
            options != ExecutionOptions.Both
        ) {
            return Status.SendNotAllowed;
        }

        // isDelegateCall && !canDelegateCall
        if (
            operation == Enum.Operation.DelegateCall &&
            options != ExecutionOptions.DelegateCall &&
            options != ExecutionOptions.Both
        ) {
            return Status.DelegateCallNotAllowed;
        }

        return Status.Ok;
    }

    function _scopedFunction(
        Role storage role,
        bytes32 key,
        uint256 value,
        bytes calldata data,
        Result memory result
    ) private view returns (Status) {
        (Condition memory condition, Consumption[] memory consumptions) = _load(
            role,
            key
        );
        ParameterPayload memory payload = Decoder.inspect(data, condition);

        result.consumptions = result.consumptions.length == 0
            ? consumptions
            : Consumptions.merge(result.consumptions, consumptions);

        return _walk(value, data, condition, payload, result);
    }

    function _walk(
        uint256 value,
        bytes calldata data,
        Condition memory condition,
        ParameterPayload memory payload,
        Result memory result
    ) private pure returns (Status) {
        Operator operator = condition.operator;

        if (operator < Operator.EqualTo) {
            if (operator == Operator.Pass) {
                return Status.Ok;
            } else if (operator == Operator.Matches) {
                return _matches(value, data, condition, payload, result);
            } else if (operator == Operator.And) {
                return _and(value, data, condition, payload, result);
            } else if (operator == Operator.Or) {
                return _or(value, data, condition, payload, result);
            } else if (operator == Operator.Nor) {
                return _nor(value, data, condition, payload, result);
            } else if (operator == Operator.Xor) {
                return _xor(value, data, condition, payload, result);
            } else if (operator == Operator.ArraySome) {
                return _arraySome(value, data, condition, payload, result);
            } else if (operator == Operator.ArrayEvery) {
                return _arrayEvery(value, data, condition, payload, result);
            } else {
                assert(operator == Operator.ArraySubset);
                return _arraySubset(value, data, condition, payload, result);
            }
        } else {
            if (operator <= Operator.LessThan) {
                return _compare(data, condition, payload);
            } else if (operator <= Operator.SignedIntLessThan) {
                return _compareSignedInt(data, condition, payload);
            } else if (operator == Operator.Bitmask) {
                return _bitmask(data, condition, payload);
            } else if (operator == Operator.Custom) {
                return _custom(value, data, condition, payload, result);
            } else if (operator == Operator.WithinAllowance) {
                return _withinAllowance(data, condition, payload, result);
            } else if (operator == Operator.EtherWithinAllowance) {
                return _etherWithinAllowance(value, condition, result);
            } else {
                assert(operator == Operator.CallWithinAllowance);
                return _callWithinAllowance(condition, result);
            }
        }
    }

    function _matches(
        uint256 value,
        bytes calldata data,
        Condition memory condition,
        ParameterPayload memory payload,
        Result memory result
    ) private pure returns (Status status) {
        if (condition.children.length != payload.children.length) {
            return Status.ParameterNotAMatch;
        }

        Consumption[] memory restore = result.consumptions;

        unchecked {
            for (uint256 i; i < condition.children.length; ++i) {
                status = _walk(
                    value,
                    data,
                    condition.children[i],
                    payload.children[i],
                    result
                );
                if (status != Status.Ok) {
                    result.consumptions = restore;
                    return status;
                }
            }
        }

        return Status.Ok;
    }

    function _and(
        uint256 value,
        bytes calldata data,
        Condition memory condition,
        ParameterPayload memory payload,
        Result memory result
    ) private pure returns (Status status) {
        Consumption[] memory restore = result.consumptions;
        unchecked {
            for (uint256 i; i < condition.children.length; ++i) {
                status = _walk(
                    value,
                    data,
                    condition.children[i],
                    payload,
                    result
                );
                if (status != Status.Ok) {
                    result.consumptions = restore;
                    return status;
                }
            }
        }
        return Status.Ok;
    }

    function _or(
        uint256 value,
        bytes calldata data,
        Condition memory condition,
        ParameterPayload memory payload,
        Result memory result
    ) private pure returns (Status) {
        Consumption[] memory restore = result.consumptions;
        unchecked {
            for (uint256 i; i < condition.children.length; ++i) {
                Status status = _walk(
                    value,
                    data,
                    condition.children[i],
                    payload,
                    result
                );
                if (status == Status.Ok) {
                    return Status.Ok;
                }
                result.consumptions = restore;
                result.info = 0;
            }
        }
        return Status.OrViolation;
    }

    function _nor(
        uint256 value,
        bytes calldata data,
        Condition memory condition,
        ParameterPayload memory payload,
        Result memory result
    ) private pure returns (Status) {
        Consumption[] memory restore = result.consumptions;
        unchecked {
            for (uint256 i; i < condition.children.length; ++i) {
                Status status = _walk(
                    value,
                    data,
                    condition.children[i],
                    payload,
                    result
                );
                if (status == Status.Ok) {
                    result.consumptions = restore;
                    result.info = 0;
                    return Status.NorViolation;
                }
            }
        }

        return Status.Ok;
    }

    function _xor(
        uint256 value,
        bytes calldata data,
        Condition memory condition,
        ParameterPayload memory payload,
        Result memory result
    ) private pure returns (Status status) {
        Consumption[] memory restore = result.consumptions;

        uint256 okCount;
        unchecked {
            for (uint256 i; i < condition.children.length; ++i) {
                Status status = _walk(
                    value,
                    data,
                    condition.children[i],
                    payload,
                    result
                );
                if (status == Status.Ok) {
                    if (++okCount > 1) {
                        break;
                    }
                }
            }
        }

        if (okCount == 1) {
            return Status.Ok;
        } else {
            result.consumptions = restore;
            result.info = 0;
            return Status.XorViolation;
        }
    }

    function _arraySome(
        uint256 value,
        bytes calldata data,
        Condition memory condition,
        ParameterPayload memory payload,
        Result memory result
    ) private pure returns (Status) {
        Consumption[] memory restore = result.consumptions;
        unchecked {
            for (uint256 i; i < payload.children.length; ++i) {
                Status status = _walk(
                    value,
                    data,
                    condition.children[0],
                    payload.children[i],
                    result
                );
                if (status == Status.Ok) {
                    return Status.Ok;
                }
                result.consumptions = restore;
                result.info = 0;
            }
        }

        return Status.NoArrayElementPasses;
    }

    function _arrayEvery(
        uint256 value,
        bytes calldata data,
        Condition memory condition,
        ParameterPayload memory payload,
        Result memory result
    ) private pure returns (Status status) {
        Consumption[] memory restore = result.consumptions;
        unchecked {
            for (uint256 i; i < payload.children.length; ++i) {
                status = _walk(
                    value,
                    data,
                    condition.children[0],
                    payload.children[i],
                    result
                );
                if (status != Status.Ok) {
                    result.consumptions = restore;
                    result.info = 0;
                    return Status.NotEveryArrayElementPasses;
                }
            }
        }
        return Status.Ok;
    }

    function _arraySubset(
        uint256 value,
        bytes calldata data,
        Condition memory condition,
        ParameterPayload memory payload,
        Result memory result
    ) private pure returns (Status) {
        if (
            payload.children.length == 0 ||
            payload.children.length > condition.children.length
        ) {
            return Status.ParameterNotSubsetOfAllowed;
        }

        Consumption[] memory restore = result.consumptions;
        unchecked {
            uint256 taken;
            for (uint256 i; i < payload.children.length; ++i) {
                bool found = false;
                for (uint256 j; j < condition.children.length; ++j) {
                    if (taken & (1 << j) != 0) continue;

                    Consumption[] memory restore_ = result.consumptions;

                    Status status = _walk(
                        value,
                        data,
                        condition.children[j],
                        payload.children[i],
                        result
                    );
                    if (status == Status.Ok) {
                        found = true;
                        taken |= 1 << j;
                        break;
                    } else {
                        result.consumptions = restore_;
                    }
                }
                if (!found) {
                    result.consumptions = restore;
                    result.info = 0;
                    return Status.ParameterNotSubsetOfAllowed;
                }
            }
        }
        return Status.Ok;
    }

    function _compare(
        bytes calldata data,
        Condition memory condition,
        ParameterPayload memory payload
    ) private pure returns (Status) {
        Operator operator = condition.operator;
        bytes32 compValue = condition.compValue;
        bytes32 value = operator == Operator.EqualTo
            ? keccak256(Decoder.pluck(data, payload.location, payload.size))
            : Decoder.word(data, payload.location);

        if (operator == Operator.EqualTo && value != compValue) {
            return Status.ParameterNotAllowed;
        } else if (operator == Operator.GreaterThan && value <= compValue) {
            return Status.ParameterLessThanAllowed;
        } else if (operator == Operator.LessThan && value >= compValue) {
            return Status.ParameterGreaterThanAllowed;
        } else {
            return Status.Ok;
        }
    }

    function _compareSignedInt(
        bytes calldata data,
        Condition memory condition,
        ParameterPayload memory payload
    ) private pure returns (Status) {
        Operator operator = condition.operator;
        int256 compValue = int256(uint256(condition.compValue));
        int256 value = int256(uint256(Decoder.word(data, payload.location)));

        if (operator == Operator.SignedIntGreaterThan && value <= compValue) {
            return Status.ParameterLessThanAllowed;
        } else if (
            operator == Operator.SignedIntLessThan && value >= compValue
        ) {
            return Status.ParameterGreaterThanAllowed;
        } else {
            return Status.Ok;
        }
    }

    /**
     * Applies a shift and bitmask on the payload bytes and compares the
     * result to the expected value. The shift offset, bitmask, and expected
     * value are specified in the compValue parameter, which is tightly
     * packed as follows:
     * <2 bytes shift offset><15 bytes bitmask><15 bytes expected value>
     */
    function _bitmask(
        bytes calldata data,
        Condition memory condition,
        ParameterPayload memory payload
    ) private pure returns (Status) {
        bytes32 compValue = condition.compValue;
        bool isInline = condition.paramType == ParameterType.Static;
        bytes calldata value = Decoder.pluck(
            data,
            payload.location + (isInline ? 0 : 32),
            payload.size - (isInline ? 0 : 32)
        );

        uint256 shift = uint16(bytes2(compValue));
        if (shift >= value.length) {
            return Status.BitmaskOverflow;
        }

        bytes32 rinse = bytes15(0xffffffffffffffffffffffffffffff);
        bytes32 mask = (compValue << 16) & rinse;
        // while its necessary to apply the rinse to the mask its not strictly
        // necessary to do so for the expected value, since we get remaining
        // 15 bytes anyway (shifting the word by 17 bytes)
        bytes32 expected = (compValue << (16 + 15 * 8)) & rinse;
        bytes32 slice = bytes32(value[shift:]);

        return
            (slice & mask) == expected ? Status.Ok : Status.BitmaskNotAllowed;
    }

    function _custom(
        uint256 value,
        bytes calldata data,
        Condition memory condition,
        ParameterPayload memory payload,
        Result memory result
    ) private pure returns (Status) {
        // 20 bytes on the left
        ICustomCondition adapter = ICustomCondition(
            address(bytes20(condition.compValue))
        );
        // 12 bytes on the right
        bytes12 extra = bytes12(uint96(uint256(condition.compValue)));

        (bool success, bytes32 info) = adapter.check(
            value,
            data,
            payload.location,
            payload.size,
            extra
        );
        result.info = info;
        return (success ? Status.Ok : Status.CustomConditionViolation);
    }

    function _withinAllowance(
        bytes calldata data,
        Condition memory condition,
        ParameterPayload memory payload,
        Result memory result
    ) private pure returns (Status) {
        uint256 value = uint256(Decoder.word(data, payload.location));
        return __consume(value, condition, result);
    }

    function _etherWithinAllowance(
        uint256 value,
        Condition memory condition,
        Result memory result
    ) private pure returns (Status status) {
        status = __consume(value, condition, result);
        return status == Status.Ok ? Status.Ok : Status.EtherAllowanceExceeded;
    }

    function _callWithinAllowance(
        Condition memory condition,
        Result memory result
    ) private pure returns (Status status) {
        status = __consume(1, condition, result);
        return (status == Status.Ok ? Status.Ok : Status.CallAllowanceExceeded);
    }

    function __consume(
        uint256 value,
        Condition memory condition,
        Result memory result
    ) private pure returns (Status) {
        Consumption[] memory consumptions = result.consumptions;
        (uint256 index, bool found) = Consumptions.find(
            consumptions,
            condition.compValue
        );
        assert(found == true);

        if (
            value + consumptions[index].consumed > consumptions[index].balance
        ) {
            result.info = consumptions[index].allowanceKey;
            return Status.AllowanceExceeded;
        } else {
            consumptions = Consumptions.clone(consumptions);
            consumptions[index].consumed += uint128(value);

            result.consumptions = consumptions;
            result.info = 0;
            return Status.Ok;
        }
    }

    struct Result {
        Consumption[] consumptions;
        bytes32 info;
    }

    enum Status {
        Ok,
        /// Role not allowed to delegate call to target address
        DelegateCallNotAllowed,
        /// Role not allowed to call target address
        TargetAddressNotAllowed,
        /// Role not allowed to call this function on target address
        FunctionNotAllowed,
        /// Role not allowed to send to target address
        SendNotAllowed,
        /// Or conition not met
        OrViolation,
        /// Nor conition not met
        NorViolation,
        /// Xor conition not met
        XorViolation,
        /// Parameter value is not equal to allowed
        ParameterNotAllowed,
        /// Parameter value less than allowed
        ParameterLessThanAllowed,
        /// Parameter value greater than maximum allowed by role
        ParameterGreaterThanAllowed,
        /// Parameter value does not match
        ParameterNotAMatch,
        /// Array elements do not meet allowed criteria for every element
        NotEveryArrayElementPasses,
        /// Array elements do not meet allowed criteria for at least one element
        NoArrayElementPasses,
        /// Parameter value not a subset of allowed
        ParameterNotSubsetOfAllowed,
        /// Bitmask exceeded value length
        BitmaskOverflow,
        /// Bitmask not an allowed value
        BitmaskNotAllowed,
        CustomConditionViolation,
        AllowanceExceeded,
        CallAllowanceExceeded,
        EtherAllowanceExceeded
    }

    /// Sender is not a member of the role
    error NoMembership();

    /// Function signature too short
    error FunctionSignatureTooShort();

    /// Calldata unwrapping failed
    error MalformedMultiEntrypoint();

    error ConditionViolation(Status status, bytes32 info);
}
