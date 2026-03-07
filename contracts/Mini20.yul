// SPDX-License-Identifier: UNLICENSED
// Compile: solc --strict-assembly --optimize Mini20.yul

object "Mini20" {
    code {
        let totalSupply := 1000000000000000000000000
        let deployer := caller()

        sstore(0, totalSupply) // totalSupply takes slot 1
        sstore(1, deployer) // deployer (also known as the owner of the contract takes slot 2)

        mstore(0, deployer) // padded to 32-byte word
        mstore(32, 2) // slot position for balances stored in memory
        // Since balances is a mapping, this becomes the seed used to compute
        // slot position for individual pair in the mapping: so...
        // slot position for the first key (say owner's balance)
        // is keccak256(k . seed) where k is the key (the owner's address)
        
        let slot := keccak256(0, 64)
        sstore(slot, totalSupply)

        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    
    object "runtime" {
        code {
            // The first 4-byte of the calldata when someone calls
            // the contract is the function selector.
            // Function selectore is the first 4 bytes of the keccak256 hash
            // of the function signature.
            let selector := shr(0xe0, calldataload(0))

            switch selector
            case 0x18160ddd {
                mstore(0, sload(0))
                return(0, 32)
            } // totalSupply()
            case 0x70a08231 {
                let addr := getAddr(0)
                mstore(0, addr)
                mstore(32, 2)
                let slot := keccak256(0, 64)
                mstore(0, sload(slot))
                return(0, 32)
            } // balanceOf(address)
            case 0xa9059cbb {
                let _to := getAddr(0)
                let _amount := calldataload(36)
                let _from := caller()

                // Ensure that _to is a zero address
                if iszero(_to) { revert(0, 0) }

                // Ensure that _to is not msg.sender
                if eq(_to, _from) { revert(0, 0) }

                // Ensure that _from balance allows this transaction
                let fromSlot := mappingSlot(_from, 2)
                let toSlot := mappingSlot(_to, 2)

                let fromBalance := sload(fromSlot)
                if lt(fromBalance, _amount) { revert(0, 0) }

                // Update balances of _to and _from
                sstore(fromSlot, sub(fromBalance, _amount))
                sstore(toSlot, add(sload(toSlot), _amount))

                // Emit Transfer(address,address,uint256) event
                mstore(0, _amount)
                log3(0, 32, 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef, _from, _to)

                mstore(0, 1)
                return(0, 32)
            } // transfer(address,uint256)
            case 0x095ea7b3 {
                let _spender := getAddr(0)
                let _amount := calldataload(36)
                let _from := caller()

                if or(iszero(_amount), iszero(_spender)) { revert(0, 0) }

                let fromSlot := mappingSlot(_from, 2)
                if lt(sload(fromSlot), _amount) { revert(0, 0) }

                let aS := allowanceSlot(_from, _spender)
                sstore(aS, _amount)

                mstore(0, _amount)
                log2(0, 32, 0x1e4109814b4fb1210f81ef6540a9bf7e5834ff79536859d16d6398f0e417c44f, _spender)
            } // approve(address,uint256)
            case 0xdd62ed3e {
                let _owner := getAddr(0)
                let _spender := getAddr(1)
                
                let aS := allowanceSlot(_owner, _spender)
                mstore(0, sload(aS))
                return(0, 32)
            } // allowance(address,address)
            case 0x23b872dd {
                let _approver := getAddr(0)
                let _to := getAddr(1)
                let _amount := calldataload(68)
                let _spender := caller()

                let aS := allowanceSlot(_approver, _spender)
                if lt(sload(aS), _amount) { revert(0, 0) }
                if iszero(_to) { revert(0, 0) }

                let approverBalanceSlot := mappingSlot(_approver, 2)
                sstore(aS, sub(sload(aS), _amount))
                sstore(approverBalanceSlot, sub(sload(approverBalanceSlot), _amount))

                mstore(0, _amount)
                log3(0, 32, 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef, _approver, _to)

                mstore(0, 1)
                return(0, 32)
            } // transferFrom(address,address,uint256)
            default { revert(0, 0) }

            function getAddr(pos) -> a {
                let offset := add(4, mul(pos, 32))
                a := and(calldataload(offset), 0xffffffffffffffffffffffffffffffffffffffff)
            }

            function mappingSlot(key, seed) -> s {
                mstore(0, key)
                mstore(32, seed)
                s := keccak256(0, 64)
            }

            function allowanceSlot(owner, spender) -> s {
                let ownerSlot := mappingSlot(owner, 3)
                s := mappingSlot(spender, ownerSlot)
            }
        }
    }
}
