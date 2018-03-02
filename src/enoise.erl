%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise).

%% API exports - Mainly mimicing gen_tcp
%% -export([ accept/1
%%         , accept/2
%%         , close/1
%%         , connect/3
%%         , connect/4
%%         , controlling_process/2
%%         , listen/2
%%         , recv/2
%%         , recv/3
%%         , send/2
%%         , shutdown/2 ]).
-compile([export_all, nowarn_export_all]).

-include("enoise.hrl").

-record(enoise, { tcp_sock, rx, tx }).

%% -type noise_hs_pattern() :: noiseNN | noiseKN.
%% -type noise_dh() :: dh448 | dh25519.
%% -type noise_cipher() :: 'AESGCM' | 'ChaChaPoly'.
%% -type noise_hash() :: sha256 | sha512 | blake2s | blake2b.

%% -type noise_protocol() :: #noise_protocol{}.

%%====================================================================
%% API functions
%%====================================================================
connect(TcpSock, Options) ->
    do_handshake(TcpSock, initiator, Options).

accept(TcpSock, Options) ->
    do_handshake(TcpSock, responder, Options).

send(E = #enoise{ tcp_sock = TcpSock, tx = TX0 }, Msg0) ->
    {ok, TX1, Msg1} = enoise_cipher_state:encrypt_with_ad(TX0, <<>>, Msg0),
    gen_tcp:send(TcpSock, <<(byte_size(Msg1)):16, Msg1/binary>>),
    E#enoise{ tx = TX1 }.

recv(E = #enoise{ tcp_sock = TcpSock, rx = RX0 }) ->
    receive {tcp, TcpSock, <<Size:16, Data/binary>>} ->
        Size = byte_size(Data),
        {ok, RX1, Msg1} = enoise_cipher_state:decrypt_with_ad(RX0, <<>>, Data),
        {E#enoise{ rx = RX1 }, Msg1}
    after 5000 -> error(timeout) end.

close(#enoise{ tcp_sock = TcpSock }) ->
    gen_tcp:close(TcpSock).


%%====================================================================
%% Internal functions
%%====================================================================
do_handshake(TcpSock, Role, Options) ->
    Prologue      = proplists:get_value(prologue, Options, <<>>),
    NoiseProtocol = proplists:get_value(noise, Options),

    S             = proplists:get_value(s, Options, undefined),
    E             = proplists:get_value(e, Options, undefined),
    RS            = proplists:get_value(rs, Options, undefined),
    RE            = proplists:get_value(re, Options, undefined),

    HSState       = enoise_hs_state:init(NoiseProtocol, Role, Prologue, {S, E, RS, RE}),
    do_handshake(TcpSock, HSState).

do_handshake(TcpSock, HState) ->
    case enoise_hs_state:next_message(HState) of
        in ->
            receive {tcp, TcpSock, Data} ->
                {ok, HState1, _Msg} = enoise_hs_state:read_message(HState, Data),
                do_handshake(TcpSock, HState1)
            after 1000 -> error(timeout) end;
        out ->
            {ok, HState1, Msg} = enoise_hs_state:write_message(HState, <<>>),
            gen_tcp:send(TcpSock, add_len(Msg)),
            do_handshake(TcpSock, HState1);
        done ->
            {ok, #{ rx := Rx, tx := Tx }} = enoise_hs_state:finalize(HState),
            {ok, #enoise{ tcp_sock = TcpSock, rx = Rx, tx = Tx }}
    end.

add_len(Msg) ->
    Len = byte_size(Msg),
    <<Len:16, Msg/binary>>.
