// SPDX-License-Identifier: UNLICENSED

object "MultiSig" {
    // ================================================================
    // STORAGE LAYOUT
    // ================================================================
    // slot 0:  _owners array length
    //          elements: keccak256(0) + index
    // slot 1:  _threshold
    // slot 2:  _nonce
    // slot 3:  _isOwner mapping anchor
    //          _isOwner[addr] = keccak256(addr . 3)
    // slot 4:  _transactions array length
    //          element I base = keccak256(4) + (I * 5)
    //            +0 creator, +1 to, +2 value, +3 data(bytes), +4 packed
    //          packed slot layout (right to left):
    //            byte 0: status, byte 1: approvals, byte 2: rejections,
    //            byte 3: executed, bytes 4-8: executedAt, bytes 9-13: createdAt
    // slot 5:  _txIndexes mapping anchor
    //          _txIndexes[id] = keccak256(id . 5)
    // slot 6:  _transactionCount
    // slot 7:  _deposits mapping anchor
    //          deposit[addr] base = keccak256(addr . 7)
    //            +0 txHash, +1 creator, +2 amount, +3 createdAt
    // slot 8:  _initialized flag (0 = no, 1 = yes, 0xffffffffffffffff = disabled)
    // slot 9:  _approvers mapping anchor
    //          inner = keccak256(txId . 9)
    //          _approvers[id][addr] = keccak256(addr . inner)
    // slot 10: _rejectors mapping anchor
    //          inner = keccak256(txId . 10)
    //          _rejectors[id][addr] = keccak256(addr . inner)
    // ================================================================

    code {
        // Permanently disable initialization on the implementation
        sstore(8, 0xffffffffffffffff)

        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }

    object "runtime" {
        code {
            mstore(0x40, 0x80)

            if iszero(calldatasize()) { stop() }

            switch selector()

            case 0x60b5bb3f { initialize() }
            case 0x7065cb48 { addOwner() }
            case 0x173825d9 { removeOwner() }
            case 0xe20056e6 { replaceOwner() }
            case 0x263a6d79 { initiateTransaction() }
            case 0x5d9ec210 { signTransaction() }
            case 0xdc61c866 { unsignTransaction() }
            case 0x05bf37aa { rejectTransaction() }
            case 0xfe0d94c1 { execute() }
            case 0xd0e30db0 { deposit() }
            case 0x1dd46c1e { getTxCount() }
            case 0x73ff81cc { getOwnersCount() }
            case 0xa0e67e2b { getOwners() }
            case 0xc41a360a { getOwner() }
            case 0x33ea3dc8 { getTransaction() }
            case 0x329a27e7 { getWalletBalance() }
            case 0xe1254fba { getDeposit() }
            case 0xb8ba16fd { getDepositAmount() }
            case 0x168a4822 { getTotalDeposits() }
            default { stop() }


            // ============================================================
            // EXTERNAL FUNCTIONS
            // ============================================================

            function initialize() {
                if sload(8) { revertWithCustom(0x0dc149f0) }
                sstore(8, 1)

                let _offset    := calldataload(4)
                let _threshold := calldataload(36)
                let _ownersLen := calldataload(add(_offset, 4))

                if lt(_ownersLen, 2) {
                    revertWithCustom(0x584bfbf4)
                }
                if or(lt(_threshold, 2), gt(_threshold, _ownersLen)) {
                    revertWithCustom(0xb891a4fb)
                }

                let _firstItemPos := add(add(_offset, 4), 32)

                for { let _i := 0 } lt(_i, _ownersLen) { _i := add(_i, 1) } {
                    let _owner := and(
                        calldataload(add(_firstItemPos, mul(_i, 32))),
                        0xffffffffffffffffffffffffffffffffffffffff
                    )

                    if iszero(_owner) { revertWithCustom(0x49e27cff) }

                    let _ownerSlot := slot(_owner, 3, 0)
                    if sload(_ownerSlot) { revertWithCustom(0xc0159e0e) }

                    sstore(_ownerSlot, 1)

                    let _currentLen := sload(0)
                    sstore(slot(0, _currentLen, 1), _owner)
                    sstore(0, add(_currentLen, 1))

                    log2(
                        0, 0,
                        0x994a936646fe87ffe4f1e469d3d6aa417d6b855598397f323de5b449f765f0c3,
                        _owner
                    )
                }

                sstore(1, _threshold)
            }

            function addOwner()            { revert(0, 0) }
            function removeOwner()         { revert(0, 0) }
            function replaceOwner()        { revert(0, 0) }
            function initiateTransaction() { revert(0, 0) }
            function signTransaction()     { revert(0, 0) }
            function unsignTransaction()   { revert(0, 0) }
            function rejectTransaction()   { revert(0, 0) }
            function execute()             { revert(0, 0) }
            function deposit()             { revert(0, 0) }
            function getTxCount()          { revert(0, 0) }
            function getOwnersCount()      { revert(0, 0) }
            function getOwners()           { revert(0, 0) }
            function getOwner()            { revert(0, 0) }
            function getTransaction()      { revert(0, 0) }
            function getWalletBalance()    { revert(0, 0) }
            function getDeposit()          { revert(0, 0) }
            function getDepositAmount()    { revert(0, 0) }
            function getTotalDeposits()    { revert(0, 0) }


            // ============================================================
            // HELPER FUNCTIONS
            // ============================================================

            function selector() -> _s {
                _s := shr(0xe0, calldataload(0))
            }

            function revertWithCustom(_s) {
                mstore(0, shl(0xe0, _s))
                revert(0, 4)
            }

            function slot(_a, _b, _dt) -> _p {
                switch _dt
                case 0 {
                    mstore(0, _a)
                    mstore(32, _b)
                    _p := keccak256(0, 64)
                }
                case 1 {
                    mstore(0, _a)
                    _p := add(keccak256(0, 32), _b)
                }
                default {
                    revert(0, 0)
                }
            }

            function roundUp32(_size) -> _rounded {
                _rounded := and(add(_size, 31), not(31))
            }

            function allocate(_size) -> _p {
                _p := mload(0x40)
                mstore(0x40, add(_p, roundUp32(_size)))
            }

            function txBaseSlot(_index) -> _s {
                _s := slot(4, mul(_index, 5), 1)
            }

            function approverSlot(_txId, _addr) -> _s {
                let _inner := slot(_txId, 9, 0)
                _s := slot(_addr, _inner, 0)
            }

            function rejectorSlot(_txId, _addr) -> _s {
                let _inner := slot(_txId, 10, 0)
                _s := slot(_addr, _inner, 0)
            }

            function depositBaseSlot(_addr) -> _s {
                _s := slot(_addr, 7, 0)
            }

            // ============================================================
            // MODIFIERS
            // ============================================================

            function requireOwner() {
                if iszero(sload(slot(caller(), 3, 0))) {
                    revertWithCustom(0x30cd7471)
                }
            }

            function requireContractOwner() {
                if iszero(eq(sload(slot(0, 0, 1)), caller())) {
                    revertWithCustom(0xbfcafd37)
                }
            }

            function requireNotInitialized() {
                if sload(8) { revert(0, 0) }
            }

            function requireTxExists(_txId) {
                let _storedIndex := sload(slot(_txId, 5, 0))
                if iszero(lt(_storedIndex, sload(4))) {
                    revertWithCustom(0x500a07ce)
                }
            }

            function requireTxNotExecuted(_txId) {
                let _txIndex  := sload(slot(_txId, 5, 0))
                let _packed   := sload(add(txBaseSlot(_txIndex), 4))
                let _executed := and(shr(0x18, _packed), 0xff)
                if _executed { revertWithCustom(0x0dc10197) }
            }

            function requireTxPending(_txId) {
                let _txIndex := sload(slot(_txId, 5, 0))
                let _packed  := sload(add(txBaseSlot(_txIndex), 4))
                let _status  := and(_packed, 0xff)
                if iszero(eq(_status, 0)) { revertWithCustom(0xa8a469d2) }
            }

            // ============================================================
            // INTERNAL FUNCTIONS
            // ============================================================

            function _addApprover(_txId, _approver) {
                let _txIndex := sload(slot(_txId, 5, 0))
                let _isApprovedSlot := approverSlot(_txId, _approver)
                if sload(_isApprovedSlot) {
                    revertWithCustom(0x101f817a)
                }

                sstore(_isApprovedSlot, 1)
                
                // Update the transaction's approvals count
                let _txPackedSlot := add(txBaseSlot(_txIndex), 4)
                let _packed := sload(_txPackedSlot)
                
                let _newApprovals := add(and(shr(0x08, _packed), 0xff), 1)
                let _cleared := and(_packed, not(shl(0x08, 0xff)))
                let _updated := or(_cleared, shl(0x08, _newApprovals))

                sstore(_txPackedSlot, _updated)
            }

            function _removeApprover(_txId, _approver) {
                let _txIndex := sload(slot(_txId, 5, 0))
                let _isApprovedSlot := approverSlot(_txId, _approver)
                if iszero(sload(_isApprovedSlot)) {
                    revertWithCustom(0x65f84cc0)
                }

                sstore(_isApprovedSlot, 0)

                // Update the transaction's approvals count
                let _txPackedSlot := add(txBaseSlot(_txIndex), 4)
                let _packed := sload(_txPackedSlot)
                
                let _newApprovals := sub(and(shr(0x08, _packed), 0xff), 1)
                let _cleared := and(_packed, not(shl(0x08, 0xff)))
                let _updated := or(_cleared, shl(0x08, _newApprovals))

                sstore(_txPackedSlot, _updated)
            }

            function _addRejector(_txId, _rejector) {
                let _txIndex := sload(slot(_txId, 5, 0))
                let _isRejectedSlot := rejectorSlot(_txId, _rejector)
                if sload(_isRejectedSlot) {
                    revertWithCustom(0x4582a780)
                }

                sstore(_isRejectedSlot, 1)

                // Update the transaction's rejections count
                let _txPackedSlot := add(txBaseSlot(_txIndex), 4)
                let _packed := sload(_txPackedSlot)

                let _newRejections := add(and(shr(0x10, _packed), 0xff), 1)
                let _cleared := and(_packed, not(shl(0x10, 0xff)))
                let _updated := or(_cleared, shl(0x10, _newRejections))
            }

            function _removeRejector(_txId, _rejector) {
                let _txIndex := sload(slot(_txId, 5, 0))
                let _isRejectedSlot := rejectorSlot(_txId, _rejector)
                if sload(_isRejectedSlot) {
                    revertWithCustom(0x4582a780)
                }

                sstore(_isRejectedSlot, 0)

                // Update the transaction's rejections count
                let _txPackedSlot := add(txBaseSlot(_txIndex), 4)
                let _packed := sload(_txPackedSlot)

                let _newRejections := sub(and(shr(0x10, _packed), 0xff), 1)
                let _cleared := and(_packed, not(shl(0x10, 0xff)))
                let _updated := or(_cleared, shl(0x10, _newRejections))
            }
        }
    }
}
