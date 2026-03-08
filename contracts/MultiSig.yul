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
    // slot 8:  _initialized flag (0 = no, 1 = yes)
    // slot 9:  _approvers mapping anchor
    //          inner = keccak256(txId . 9)
    //          _approvers[id][addr] = keccak256(addr . inner)
    // slot 10: _rejectors mapping anchor
    //          inner = keccak256(txId . 10)
    //          _rejectors[id][addr] = keccak256(addr . inner)
    // ================================================================

    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }

    object "runtime" {
        code {
            // Initialize the free memory pointer.
            // Solidity convention: 0x40 always holds the next free memory position.
            // We start at 0x80 because 0x00-0x3f is scratch space and
            // 0x40-0x5f is the pointer itself, 0x60-0x7f is reserved zero slot.
            mstore(0x40, 0x80)

            if iszero(calldatasize()) { stop() }

            switch selector()

            // ── Initialization ──────────────────────────────────────
            case 0x60b5bb3f { initialize() }

            // ── Owner Management ────────────────────────────────────
            case 0x7065cb48 { addOwner() }
            case 0x173825d9 { removeOwner() }
            case 0xe20056e6 { replaceOwner() }

            // ── Transaction Lifecycle ────────────────────────────────
            case 0x263a6d79 { initiateTransaction() }
            case 0x5d9ec210 { signTransaction() }
            case 0xdc61c866 { unsignTransaction() }
            case 0x05bf37aa { rejectTransaction() }
            case 0xfe0d94c1 { execute() }

            // ── Deposits ─────────────────────────────────────────────
            case 0xd0e30db0 { deposit() }

            // ── View Functions ────────────────────────────────────────
            case 0x1dd46c1e { getTxCount() }
            case 0x73ff81cc { getOwnersCount() }
            case 0xa0e67e2b { getOwners() }
            case 0xc41a360a { getOwner() }
            case 0x33ea3dc8 { getTransaction() }
            case 0x329a27e7 { getWalletBalance() }
            case 0xe1254fba { getDeposit() }
            case 0xb8ba16fd { getDepositAmount() }
            case 0x168a4822 { getTotalDeposits() }

            // ── Fallback ──────────────────────────────────────────────
            default { stop() }


            // ============================================================
            // EXTERNAL FUNCTIONS
            // ============================================================

            function initialize() {
                if sload(8) {
                    revertWithCustom(0x0dc149f0)
                }

                sstore(8, 1)

                let _offset := calldataload(4)
                let _threshold := calldataload(36)
                let _ownersLen := calldataload(add(_offset, 4))
                
                if lt(_ownersLen, 2) { revertWithCustom(0x584bfbf4) }
                if or(lt(_threshold, 2), gt(_threshold, _ownersLen)) { revertWithCustom(0xb891a4fb) }

                let _firstItemPos := add(add(_offset, 4), 32)
                for {let i := 0} lt(i, _ownersLen) {i := add(i, 1)} {
                    let _owner := and(
                        calldataload(add(_firstItemPos, mul(i, 32))),
                        0xffffffffffffffffffffffffffffffffffffffff
                    )
                    if iszero(_owner) { revertWithCustom(0x49e27cff) }
                    
                    let _ownerSlot := slot(_owner, 3, 0)
                    if sload(_ownerSlot) {
                        revertWithCustom(0xc0159e0e)
                    }

                    sstore(_ownerSlot, 1)

                    let _currentLen := sload(0)
                    sstore(slot(0, _currentLen, 1), _owner)
                    sstore(0, add(_currentLen, 1))

                    // Event signature: keccak256("OwnerAdded(address)") = 0x994a9366...
                    log2(0, 0,
                        0x994a936646fe87ffe4f1e469d3d6aa417d6b855598397f323de5b449f765f0c3,
                        _owner
                    )
                }
            }

            function addOwner()           { revert(0, 0) }
            function removeOwner()        { revert(0, 0) }
            function replaceOwner()       { revert(0, 0) }
            function initiateTransaction(){ revert(0, 0) }
            function signTransaction()    { revert(0, 0) }
            function unsignTransaction()  { revert(0, 0) }
            function rejectTransaction()  { revert(0, 0) }
            function execute()            { revert(0, 0) }
            function deposit()            { revert(0, 0) }
            function getTxCount()         { revert(0, 0) }
            function getOwnersCount()     { revert(0, 0) }
            function getOwners()          { revert(0, 0) }
            function getOwner()           { revert(0, 0) }
            function getTransaction()     { revert(0, 0) }
            function getWalletBalance()   { revert(0, 0) }
            function getDeposit()         { revert(0, 0) }
            function getDepositAmount()   { revert(0, 0) }
            function getTotalDeposits()   { revert(0, 0) }


            // ============================================================
            // HELPER FUNCTIONS
            // ============================================================

            // Extracts the 4-byte function selector from calldata
            function selector() -> s {
                s := shr(0xe0, calldataload(0))
            }

            // Reverts with a 4-byte custom error selector.
            // Pass the selector as a plain 4-byte number e.g. 0x30cd7471
            // shl(0xe0, s) shifts it left 28 bytes so it sits in the
            // highest 4 bytes of the 32-byte memory word, which is
            // correct ABI encoding for a bare error selector.
            function revertWithCustom(s) {
                mstore(0, shl(0xe0, s))
                revert(0, 4)
            }

            // Computes storage slot for mappings and array elements.
            // dt=0 (mapping): keccak256(key . mappingSlot)
            //   a = key, b = the mapping's storage slot number
            // dt=1 (array):   keccak256(arraySlot) + index
            //   a = the array's storage slot number, b = index
            function slot(a, b, dt) -> p {
                switch dt
                case 0 {
                    mstore(0, a)
                    mstore(32, b)
                    p := keccak256(0, 64)
                }
                case 1 {
                    mstore(0, a)
                    p := add(keccak256(0, 32), b)
                }
                default {
                    revert(0, 0)
                }
            }

            // Rounds size up to the nearest 32-byte boundary.
            // Used whenever allocating memory to keep everything aligned.
            function roundUp32(size) -> rounded {
                rounded := and(add(size, 31), not(31))
            }

            // Allocates a region of memory of `size` bytes.
            // Reads the free memory pointer at 0x40, returns the current
            // position as the allocation start, then advances the pointer
            // by size rounded up to 32 bytes.
            function allocate(size) -> p {
                p := mload(0x40)
                mstore(0x40, add(p, roundUp32(size)))
            }

            // Reverts unless caller is a registered owner
            function requireOwner() {
                if iszero(sload(slot(caller(), 3, 0))) {
                    revertWithCustom(0x30cd7471)
                }
            }

            // Reverts unless caller is owners[0] (the contract owner)
            function requireContractOwner() {
                // slot(0, 0, 1): array at storage slot 0, element at index 0
                if iszero(eq(sload(slot(0, 0, 1)), caller())) {
                    revertWithCustom(0xbfcafd37)
                }
            }

            // Reverts if the contract has already been initialized
            function requireNotInitialized() {
                if sload(8) { revert(0, 0) }
            }

            // Base storage slot for transaction at array index `index`
            // Each transaction occupies 5 consecutive slots
            function txBaseSlot(index) -> s {
                s := slot(4, mul(index, 5), 1)
            }

            // Storage slot for _approvers[txId][addr]
            function approverSlot(txId, addr) -> s {
                let inner := slot(txId, 9, 0)
                s := slot(addr, inner, 0)
            }

            // Storage slot for _rejectors[txId][addr]
            function rejectorSlot(txId, addr) -> s {
                let inner := slot(txId, 10, 0)
                s := slot(addr, inner, 0)
            }

            // Base storage slot for deposit of `addr`
            function depositBaseSlot(addr) -> s {
                s := slot(addr, 7, 0)
            }
        }
    }
}