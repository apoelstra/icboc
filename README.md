
# Icebox

Icebox is a cold wallet designed to work with the Ledger Nano S on an offline
computer. It is designed for power users willing to do a fair bit of work to
send transactions. Currently it is under development and it is strongly
discouraged to use it. In particular, there is no support for sending coins,
so if you send coins to this wallet, *you will need to write the code to
retrieve them*.

It is designed around the principle that each address corresponds to one
payment, and while address should appear uniformly random, the wallet should
tie this information to the address in a verifiable, untamperable way.

To protect privacy, each wallet is created with support for a fixed number
of addresses. Initially an encrypted block of zeroes is stored in place of
the address information so that the size of the wallet file never changes.

All keys are stored on the dongle; what the "wallet" stores on the PC is a
database of information about addresses that have been used.

## Version 1

The first version of Icebox is designed to work with the Bitcoin app that comes
with the Nano S, whose [source code is available here](https://github.com/LedgerHQ/blue-app-btc/issues).
As such, it will not be able to do everything that Icebox is eventually intended
to do. Its features are

 - [x] Generate addresses, prompting the user for some extra information to tag it with
 - [x] Sign said information with the address and store this in an encrypted form
 - [x] Display information, including verifying the signature, about generated addresses
 - [x] Error out when the user attempts to generate the same address twice
 - [ ] Search wallet by address rather than BIP32 index
 - [ ] Update wallet when payment is received to note txid/vout/amount
 - [ ] Allow extending the wallet to add more address entries
 - [ ] Sign transactions

## Version 2

The next version of Icebox will include its own Ledger application which will
fork the Bitcoin app to add some extra functionality.

 - [ ] Do decryption/encryption on the dongle rather than querying for encryption keys
 - [ ] Commit to data in the address itself via pay-to-contract rather than just signing it
 - [ ] Detect and warn when a wallet has been restored from an out-of-date backup
 - [ ] Faster lookup of next-unused-index


