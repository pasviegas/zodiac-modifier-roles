// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.8.17 <0.9.0;

interface ISingletonFactory {
    function deploy(
        bytes memory initCode,
        bytes32 salt
    ) external returns (address);
}

library WriteOnce {
    address public constant SINGLETON_FACTORY =
        0xce0042B868300000d44A59004Da54A005ffdcf9f;

    bytes32 public constant SALT =
        0xbadfed0000000000000000000000000000000000000000000000000000badfed;

    /**
    @notice Stores `_data` and returns `pointer` as key for later retrieval
    @dev The pointer is a contract address with `_data` as code
    @param data to be written
    @return pointer Pointer to the written `data`
  */
    function store(bytes memory data) internal returns (address pointer) {
        bytes memory creationBytecode = creationBytecodeFor(data);
        address calculatedAddress = addressFor(creationBytecode);

        uint256 size;
        assembly {
            size := extcodesize(calculatedAddress)
        }

        address actualAddress;
        if (size == 0) {
            actualAddress = ISingletonFactory(SINGLETON_FACTORY).deploy(
                creationBytecode,
                SALT
            );
        } else {
            actualAddress = calculatedAddress;
        }

        assert(calculatedAddress == actualAddress);

        pointer = calculatedAddress;
    }

    /**
    @notice Reads the contents of the `pointer` code as data, skips the first byte
    @dev The function is intended for reading pointers generated by `write`
    @param pointer to be read
    @return data read from `pointer` contract
  */
    function load(address pointer) internal view returns (bytes memory) {
        return runtimeBytecodeAt(pointer);
    }

    function runtimeBytecodeAt(
        address pointer
    ) private view returns (bytes memory result) {
        // jump over the 00
        uint256 skip = 1;
        unchecked {
            uint256 size;
            assembly {
                size := extcodesize(pointer)
            }
            assert(size > 1);

            result = new bytes(size - skip);
            assembly {
                extcodecopy(pointer, add(result, 0x20), skip, size)
            }
        }
    }

    function addressFor(
        bytes memory creationBytecode
    ) private pure returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                SINGLETON_FACTORY,
                SALT,
                keccak256(creationBytecode)
            )
        );
        // get the right most 20 bytes
        return address(uint160(uint256(hash)));
    }

    /**
    @notice Generate a creation code that results on a contract with `data` as bytecode
    @param data sdsd
    @return creationBytecode (constructor) for new contract
    */
    function creationBytecodeFor(
        bytes memory data
    ) private pure returns (bytes memory) {
        /*
      0x00    0x63         0x63XXXXXX  PUSH4 _code.length  size
      0x01    0x80         0x80        DUP1                size size
      0x02    0x60         0x600e      PUSH1 14            14 size size
      0x03    0x60         0x6000      PUSH1 00            0 14 size size
      0x04    0x39         0x39        CODECOPY            size
      0x05    0x60         0x6000      PUSH1 00            0 size
      0x06    0xf3         0xf3        RETURN
      <CODE>
    */

        return
            abi.encodePacked(
                hex"63",
                uint32(data.length + 1),
                hex"80_60_0E_60_00_39_60_00_F3",
                // Append 00 to data so contract can't be called
                hex"00",
                data
            );
    }
}
