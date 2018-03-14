enoise
=====

An Erlang implementation of the [Noise protocol](https://noiseprotocol.org/)

`enoise` provides a generic handshake mechanism, that can be used in a couple
of different ways. There is also a plain `gen_tcp`-wrapper, where you can
"upgrade" a TCP socket to a Noise socket and use it in much the same way as you
would use `gen_tcp`.

Interactive handshake
---------------------

When using `enoise` to do an interactive handshake, `enoise` will only take
care of message composition/decompositiona and encryption/decryption - i.e. the
user has to do the actual sending and receiving.

An example of the interactive handshake can be seen in the `noise_interactive`
test in `test/enoise_tests.erl`.

Generic handshake
-----------------

There is also the option to use an automated handshake procedure. If provided
with a generic _Communication state_ that describe how data is sent and
received, the handshake procedure is done automatically. The result of a
successful handshake is two Cipher states that can be used to encrypt/decrypt a
RX channel and a TX channel respectively.

The provided `gen_tcp`-wrapper is implemented using the generic handshake, see
`src/enoise.erl`.

Build
-----

    $ rebar3 compile

Test
----

    $ rebar3 eunit
