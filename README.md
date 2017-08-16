
# ICBOC

ICBOC, or "Ice Cold Box of Coins", was originally named Icebox, but it turned
out that this collided with the pre-existing [Icebox project](https://github.com/ConsenSys/icebox).
The current name was chosen to be awkward enough to avoid collisions, while
still sounding kinda like "icebox".

ICBOC is a cold wallet designed to work with the Ledger Nano S on an offline
computer. It is designed for power users willing to do a fair bit of work to
send transactions. Currently it is under development and it is strongly
discouraged to use it.

It is designed around the principle that each address corresponds to one
payment, and while address should appear uniformly random, the wallet should
tie this information to the address in a verifiable, untamperable way.

To protect privacy, each wallet is created with support for a fixed number
of addresses. Initially an encrypted block of zeroes is stored in place of
the address information so that the size of the wallet file never changes.

All keys are stored on the dongle; what the "wallet" stores on the PC is a
database of information about addresses that have been used.

## Usage

To generate a new wallet, choose a BIP44 account number and a number of
address to support initially.

    icboc wallet.icboc.dat init 0 100

To get a new address, do

    icboc wallet.icboc.dat getaddress

This will prompt you for some information and eventually output an address
entry:

    Signed Entry:
       index: 0
     address: 1EfxCKm257NbVJhJCVMzyhkvuJh1j6Zyx
        txid: no associated output
     created: 2017-03-29 16:28:10-0000
     (after): 0000000000000000024068e6d589797e2b1d9a52498c65b5ef5600caedb37aee
        user: apoelstra@home
        note: payment for whats-its-contract

You can retrieve this at any time by using its index:

    icboc wallet.icboc.dat info 0

or by its address (though this will require retrieving addresses from the
dongle until it's found, there is no index for privacy reasons):

    icboc wallet.icboc.dat info 1EfxCKm257NbVJhJCVMzyhkvuJh1j6Zyx

Later, if you receive coins to this address, you can inform the wallet by
giving it the entire hex-encoded rawtransaction. The entire transaction is
required by the Ledger because this is the only way it can confirm the
input values it's signing off on, when signing coins. (One of the many
SegWit provides is to fix this inconvenience.)

    icboc wallet.icboc.dat receive 02000000011aef8cfaec49ab111d6240c6ce609d430c7ec990307dfca6f6addb7c82152e710000000000feffffff02935b9800000000001976a9141285a7fe04cd6df5e5b93b56bc0ef171332e85f588ac40597307000000001976a9140295ec35d638c16b25608b4e362a214a5692d20088ac00000000

The wallet will read the transaction, detect which outputs belong to it,
and update the appropriate entries:

    17:04:24 [INFO] Receive to entry 0. Amount 125000000, outpoint 6350216a48084eb1998cc2e90a76e5a7b6591100d738615c59eec2097d4f18c5:1!

It will ask you to re-sign for any entries that changed. The entries are
updated to reflect the unspent output information, as

    Signed Entry:
       index: 0
     address: 1EfxCKm257NbVJhJCVMzyhkvuJh1j6Zyx
        txid: 6350216a48084eb1998cc2e90a76e5a7b6591100d738615c59eec2097d4f18c5
        vout: 1
       spent: false
      amount: 125000000
     created: 2017-03-29 16:28:10-0000
     (after): 0000000000000000024068e6d589797e2b1d9a52498c65b5ef5600caedb37aee
        user: apoelstra@home
        note: payment for whats-its-contract
                                            


## Version 1

The first version of ICBOC is designed to work with the Bitcoin app that comes
with the Nano S, whose [source code is available here](https://github.com/LedgerHQ/blue-app-btc/issues).
As such, it will not be able to do everything that ICBOC is eventually intended
to do. Its features are

 - [x] Generate addresses, prompting the user for some extra information to tag it with
 - [x] Sign said information with the address and store this in an encrypted form
 - [x] Display information, including verifying the signature, about generated addresses
 - [x] Error out when the user attempts to generate the same address twice
 - [x] Search wallet by address rather than BIP32 index
 - [x] Update wallet when payment is received to note txid/vout/amount
 - [x] Allow extending the wallet to add more address entries
 - [x] Sign transactions

## Version 2

The next version of ICBOC will include its own Ledger application which will
fork the Bitcoin app to add some extra functionality.

 - [ ] Do decryption/encryption on the dongle rather than querying for encryption keys
 - [ ] Commit to data in the address itself via pay-to-contract rather than just signing it
 - [ ] Use sign-to-contract to support [Greg's sidechannel-blocking nonce choosing scheme](https://botbot.me/freenode/secp256k1/2017-08-12/?msg=89759015&page=1)
 - [ ] Detect and warn when a wallet has been restored from an out-of-date backup
 - [ ] Faster lookup of next-unused-index


