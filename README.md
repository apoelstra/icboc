
# ICBOC 3D

ICBOC 3D, or "Ice Cold Box of Coins Descriptors Descriptors Descriptors",
was originally named Icebox, but this collided with some old ConsenSys
project. Unsurprising, given that it's a natural name for a cold wallet.

The current name was chosen to be awkward enough to avoid collisions, while
still sounding kinda like "icebox". In 2021, it was rewritten to work with
descriptors, and the suffix 3D was added.

ICBOC 3D is a cold wallet designed to work with the Ledger Nano S on an offline
computer. It is designed for power users willing to do a fair bit of work to
send transactions. Currently it is under development and it is strongly
discouraged to use it.

All keys are stored on the dongle; what the "wallet" stores on the PC is a
database of information about addresses that have been used.

Since ICBOC 3D, you can compile with the "jsonrpc" cargo feature flag and
it will scan the blockchain for you by connecting to a local bitcoind. This
is not necessary.

## Usage

To generate a new wallet, just run

    icboc3d wallet.icboc.dat init

Both commands will request you sign a fixed hash with a curiously large
number of 0 bytes in it. This signature is used as an encryption key for
the wallet, since this was the cleanest way I could think of to get
key-like material from the Nano S and require user action when getting it.
(Actual public keys, addresses, chaincodes, etc., can all be obtained
from the Ledger without user intervention.)

The `init` command (and all commands) will output a master public key, such as

    Master xpub: xpub661MyMwAqRbcFNH5PfeY7Nq2aDmC98jGbLe7ApvS7LnRnf2NNw9HUPyr6AycFzkchy4vn23J2HSxQRMSsVsRJZ4ihoZoJEnAnMYtmLWmSg7

You can use this key to generate a descriptor which you can import, e.g.

    icboc3d wallet.icboc.dat importdescriptor '{"desc": "pkh(xpub661MyMwAqRbcFNH5PfeY7Nq2aDmC98jGbLe7ApvS7LnRnf2NNw9HUPyr6AycFzkchy4vn23J2HSxQRMSsVsRJZ4ihoZoJEnAnMYtmLWmSg7/44h/0h/0h/1/*)", "range_low": 0, "range_high": 100}'

Currently icboc only supports the `pkh` descriptor, though we will add
support for `wpkh` soon. Going further than that may be difficult with
the Ledger Nano S, which makes a lot of faulty assumptions about what
Bitcoin transactions are made of.

Once you've imported a descriptor, you can see it with

    icboc3d wallet.icboc.dat info

You'll see that each descriptor has an index, which is used to identify it in
the wallet. When there is only one descriptor it will have index 0. You can
get a new address from it by running

    icboc3d wallet.icboc.dat getnewaddress '{ "descriptor": 0 }'

Then receive coins either by copying raw transactions and running

    icboc3d wallet.icboc.dat receive '{ "tx": "<hex string>" }'

or by compiling with the `jsonrpc` cargo feature, setting up a bitcoind with
a RPC auth cookie in `~/.bitcoin/.cookie`, and running

    icboc3d wallet.icboc.dat rescan '{ "start_from": 630000 }'

where the `start_from` argument may be omitted (though this will take a very
long time).

## Spending coins

You can see your available coins with

    icboc3d wallet.icboc.dat listunspent

Create a new transaction from these by getting a new change address and then
using `bitcoin-cli` or `hal` or whatever to construct a raw transaction. Then
run

    icboc3d wallet.icboc.dat signrawtransaction '{ "tx": "<hex string>" }'

ICBOC 3D is smart enough to recognize its own change addresses, though the
Nano S requires there be only one, and that it use a `pkh` descriptor. Once
signed, you can broadcast the raw transaction however you like, and then
inform ICBOC 3D about it by running

    icboc3d wallet.icboc.dat receive '{ "tx": "<hex string of signed tx>" }'

## Migrating from ICBOC

You can import the descriptor and all your notes from an old ICBOC wallet by
running

    icboc3d wallet.icboc.dat importicboc '{ "file":"old-icboc-wallet.dat" }'

