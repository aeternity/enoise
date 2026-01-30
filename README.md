enoise
=====

An Erlang implementation of the [Noise protocol](https://noiseprotocol.org/)

**Requires OTP 27+**

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

PSK (Pre-Shared Key) Handshake
------------------------------

For patterns that require a pre-shared key (e.g., `NNpsk0`, `NKpsk2`), provide
the PSK in the options:

```erlang
%% PSK handshake with NNpsk0 pattern
Options = [{noise, "Noise_NNpsk0_25519_ChaChaPoly_SHA256"},
           {psk, <<"my-pre-shared-key-32-bytes-long!">>}],
{ok, HState} = enoise:handshake(Options, initiator).
```

The PSK must be exactly 32 bytes. For patterns with multiple PSK tokens, use
`{psks, [binary()]}` to provide multiple keys in order.

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

Typecheck
---------

    $ rebar3 dialyzer
    $ elp --eqwalize-all --rebar
