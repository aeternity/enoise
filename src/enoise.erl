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
connect(Address, Port, Options) ->
    connect(Address, Port, Options, infinity).


connect(Address, Port, Options, Timeout) ->
    case initiate_handshake(initiator, Options) of
        {ok, HS} ->
            TcpOpts = enoise_opts:tcp_opts(Options),
            case gen_tcp:connect(Address, Port, TcpOpts, Timeout) of
                {ok, TcpSock} ->
                    do_handshake(TcpSock, HS, Options);
                Err = {error, _Reason} ->
                    Err
            end;
        Err = {error, _Reason} ->
            Err
    end.

send(E = #enoise{ tcp_sock = TcpSock, rx = RX0 }, Msg0) ->
    {ok, RX1, Msg1} = enoise_cipher_state:encrypt_with_ad(RX0, <<>>, Msg0),
    gen_tcp:send(TcpSock, <<(byte_size(Msg1)):16, Msg1/binary>>),
    E#enoise{ rx = RX1 }.

recv(E = #enoise{ tcp_sock = TcpSock, tx = TX0 }) ->
    receive {tcp, TcpSock, <<Size:16, Data/binary>>} ->
        Size = byte_size(Data),
        {ok, TX1, Msg1} = enoise_cipher_state:decrypt_with_ad(TX0, <<>>, Data),
        {E#enoise{ tx = TX1 }, Msg1}
    after 1000 -> error(timeout) end.

close(#enoise{ tcp_sock = TcpSock }) ->
    gen_tcp:close(TcpSock).


%%====================================================================
%% Internal functions
%%====================================================================
initiate_handshake(Role, Options) ->
    Prologue      = proplists:get_value(prologue, Options, <<>>),
    NoiseProtocol = proplists:get_value(noise, Options),

    S             = proplists:get_value(s, Options, undefined),
    E             = proplists:get_value(e, Options, undefined),
    RS            = proplists:get_value(rs, Options, undefined),
    RE            = proplists:get_value(re, Options, undefined),

    HSState       = enoise_hs_state:init(NoiseProtocol, Role, Prologue, {S, E, RS, RE}),
    {ok, HSState}.


do_handshake(TcpSock, HState, Options) ->
    PreComm       = proplists:get_value(pre_comm, Options, <<>>), %% TODO: Not standard!

    gen_tcp:send(TcpSock, PreComm),

    do_handshake(TcpSock, HState).


do_handshake(TcpSock, HState) ->
    case enoise_hs_state:next_message(HState) of
        in ->
            receive {tcp, TcpSock, Data} ->
                case enoise_hs_state:read_message(HState, Data) of
                    {ok, HState1, _Msg} ->
                        do_handshake(TcpSock, HState1);
                    {done, _HState1, _Msg, {C1, C2}} ->
                        {ok, #enoise{ tcp_sock = TcpSock, rx = C1, tx = C2 }}
                end
            after 1000 ->
                error(timeout)
            end;
        out ->
            case enoise_hs_state:write_message(HState, <<>>) of
                {ok, HState1, Msg} ->
                    io:format("Sending: ~p\n", [add_len(Msg)]),
                    gen_tcp:send(TcpSock, add_len(Msg)),
                    do_handshake(TcpSock, HState1);
                {done, _HState1, Msg, {C1, C2}} ->
                    io:format("Sending: ~p\n", [add_len(Msg)]),
                    gen_tcp:send(TcpSock, add_len(Msg)),
                    {ok, #enoise{ tcp_sock = TcpSock, rx = C1, tx = C2 }}
            end
    end.

add_len(Msg) ->
    Len = byte_size(Msg),
    <<Len:16, Msg/binary>>.
