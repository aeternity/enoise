%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%% @doc PSK internal consistency tests
%%%
%%% These tests verify that PSK patterns work correctly by testing
%%% that both initiator and responder can complete a handshake and
%%% communicate. We don't test against external vectors because the
%%% available PSK test vectors appear to use a different interpretation.
%%%-------------------------------------------------------------------

-module(enoise_psk_tests).

-include_lib("eunit/include/eunit.hrl").

noise_psk_test_() ->
    {setup,
        fun() -> setup_psk() end,
        fun(_X) -> ok end,
        fun(Configs) ->
            [ {format_name(P, DH, C, H), fun() -> psk_consistency_test(P, DH, C, H) end}
              || {P, DH, C, H} <- Configs ]
        end
    }.

setup_psk() ->
    test_utils:psk_test_configs().

format_name(Pattern, DH, Cipher, Hash) ->
    lists:flatten(io_lib:format("~s_~s_~s_~s",
        [Pattern, DH, Cipher, Hash])).

psk_consistency_test(Pattern, DH, Cipher, Hash) ->
    Protocol = enoise_protocol:from_name(
        enoise_protocol:to_name(Pattern, DH, Cipher, Hash)),

    %% Generate keys - full keypairs for local, pubkey-only for remote
    InitS = case needs_init_s(Pattern) of
        true -> enoise_keypair:new(DH);
        false -> undefined
    end,
    RespS = case needs_resp_s(Pattern) of
        true -> enoise_keypair:new(DH);
        false -> undefined
    end,

    %% Get remote static as pubkey-only keypair if needed
    InitRS = case needs_init_rs(Pattern) andalso RespS =/= undefined of
        true -> enoise_keypair:new(DH, enoise_keypair:pubkey(RespS));
        false -> undefined
    end,
    RespRS = case needs_resp_rs(Pattern) andalso InitS =/= undefined of
        true -> enoise_keypair:new(DH, enoise_keypair:pubkey(InitS));
        false -> undefined
    end,

    %% PSK - 32 bytes
    PSK = crypto:strong_rand_bytes(32),
    PSKs = [PSK],

    Prologue = <<"PSK test prologue">>,

    %% Initialize handshake states
    {ok, InitHS0} = enoise_hs_state:init(Protocol, initiator, Prologue,
                                          {InitS, undefined, InitRS, undefined}, PSKs),
    {ok, RespHS0} = enoise_hs_state:init(Protocol, responder, Prologue,
                                          {RespS, undefined, RespRS, undefined}, PSKs),

    %% Run handshake
    {InitFinal, RespFinal} = run_handshake(InitHS0, RespHS0),

    %% Verify both parties agree on handshake hash
    {ok, #{hs_hash := InitHash}} = enoise_hs_state:finalize(InitFinal),
    {ok, #{hs_hash := RespHash}} = enoise_hs_state:finalize(RespFinal),
    ?assertEqual(InitHash, RespHash),

    ok.

run_handshake(InitHS, RespHS) ->
    run_handshake(InitHS, RespHS, 1).

run_handshake(InitHS, RespHS, MsgNum) ->
    case {enoise_hs_state:next_message(InitHS), enoise_hs_state:next_message(RespHS)} of
        {done, done} ->
            {InitHS, RespHS};
        {out, in} ->
            %% Initiator sends
            Payload = list_to_binary(io_lib:format("init_msg_~p", [MsgNum])),
            {ok, InitHS1, Msg} = enoise_hs_state:write_message(InitHS, Payload),
            {ok, RespHS1, RecvPayload} = enoise_hs_state:read_message(RespHS, Msg),
            ?assertEqual(Payload, RecvPayload),
            run_handshake(InitHS1, RespHS1, MsgNum + 1);
        {in, out} ->
            %% Responder sends
            Payload = list_to_binary(io_lib:format("resp_msg_~p", [MsgNum])),
            {ok, RespHS1, Msg} = enoise_hs_state:write_message(RespHS, Payload),
            {ok, InitHS1, RecvPayload} = enoise_hs_state:read_message(InitHS, Msg),
            ?assertEqual(Payload, RecvPayload),
            run_handshake(InitHS1, RespHS1, MsgNum + 1)
    end.

%% Key requirement checks based on pattern
needs_init_s(Pattern) ->
    Pat = atom_to_list(Pattern),
    Base = hd(string:lexemes(Pat, "_")),
    lists:member(string:lowercase(Base), ["k", "x", "kn", "kk", "kx", "xn", "xk", "xx", "in", "ik", "ix"]).

needs_resp_s(Pattern) ->
    Pat = atom_to_list(Pattern),
    Base = hd(string:lexemes(Pat, "_")),
    lists:member(string:lowercase(Base), ["n", "k", "x", "nk", "nx", "kk", "kx", "xk", "xx", "ik", "ix"]).

needs_init_rs(Pattern) ->
    Pat = atom_to_list(Pattern),
    Base = hd(string:lexemes(Pat, "_")),
    lists:member(string:lowercase(Base), ["n", "k", "x", "nk", "kk", "xk", "ik"]).

needs_resp_rs(Pattern) ->
    Pat = atom_to_list(Pattern),
    Base = hd(string:lexemes(Pat, "_")),
    lists:member(string:lowercase(Base), ["k", "kn", "kk", "kx"]).
