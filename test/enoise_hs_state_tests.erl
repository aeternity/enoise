%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_hs_state_tests).

-include_lib("eunit/include/eunit.hrl").

noise_hs_test_() ->
    %% Test vectors from https://raw.githubusercontent.com/rweather/noise-c/master/tests/vector/noise-c-basic.txt
    {setup,
        fun() -> test_utils:noise_test_vectors() end,
        fun(_X) -> ok end,
        fun(Tests) ->
            [ {maps:get(protocol_name, T), fun() -> noise_hs_test(T) end}
              || T <- test_utils:noise_test_filter(Tests) ]
        end
    }.

noise_hs_test(V = #{ protocol_name := Name }) ->
    Protocol = enoise_protocol:from_name(Name),

    FixK = fun(undefined) -> undefined;
              (Bin) -> test_utils:hex_str_to_bin("0x" ++ binary_to_list(Bin)) end,

    Init = #{ prologue => FixK(maps:get(init_prologue, V, <<>>))
            , e        => FixK(maps:get(init_ephemeral, V, undefined))
            , s        => FixK(maps:get(init_static, V, undefined))
            , rs       => FixK(maps:get(init_remote_static, V, undefined)) },
    Resp = #{ prologue => FixK(maps:get(resp_prologue, V, <<>>))
            , e        => FixK(maps:get(resp_ephemeral, V, undefined))
            , s        => FixK(maps:get(resp_static, V, undefined))
            , rs       => FixK(maps:get(resp_remote_static, V, undefined)) },
    Messages = maps:get(messages, V),
    HandshakeHash = maps:get(handshake_hash, V),

    noise_test(Name, Protocol, Init, Resp, Messages, FixK(HandshakeHash)),

    ok.

noise_test(_Name, Protocol, Init, Resp, Messages, HSHash) ->
    DH = enoise_protocol:dh(Protocol),
    SecK = fun(undefined) -> undefined; (Sec) -> enoise_keypair:new(DH, Sec, undefined) end,
    PubK = fun(undefined) -> undefined; (Pub) -> enoise_keypair:new(DH, Pub) end,
    HSInit = fun(P, R, #{ e := E, s := S, rs := RS, prologue := PL }) ->
                enoise_hs_state:init(P, R, PL, {SecK(S), SecK(E), PubK(RS), undefined})
             end,

    InitHS = HSInit(Protocol, initiator, Init),
    RespHS = HSInit(Protocol, responder, Resp),

    noise_test(Messages, InitHS, RespHS, HSHash),

    ok.

noise_test([M = #{ payload := PL0, ciphertext := CT0 } | Msgs], SendHS, RecvHS, HSHash) ->
    PL = test_utils:hex_str_to_bin("0x" ++ binary_to_list(PL0)),
    CT = test_utils:hex_str_to_bin("0x" ++ binary_to_list(CT0)),
    case {enoise_hs_state:next_message(SendHS), enoise_hs_state:next_message(RecvHS)} of
        {out, in} ->
            {ok, SendHS1, Message} = enoise_hs_state:write_message(SendHS, PL),
            ?assertEqual(CT, Message),
            {ok, RecvHS1, PL1} = enoise_hs_state:read_message(RecvHS, Message),
            ?assertEqual(PL, PL1),
            noise_test(Msgs, RecvHS1, SendHS1, HSHash);
        {done, done} ->
            {ok, #{ rx := RX1, tx := TX1, hs_hash := HSHash1 }} = enoise_hs_state:finalize(SendHS),
            {ok, #{ rx := RX2, tx := TX2, hs_hash := HSHash2 }} = enoise_hs_state:finalize(RecvHS),
            ?assertEqual(RX1, TX2), ?assertEqual(RX2, TX1),
            ?assertEqual(HSHash, HSHash1), ?assertEqual(HSHash, HSHash2),
            noise_test([M | Msgs], TX1, RX1);
        {Out, In} -> ?assertMatch({out, in}, {Out, In})
    end.

noise_test([], _, _) -> ok;
noise_test([#{ payload := PL0, ciphertext := CT0 } | Msgs], CA, CB) ->
    PL = test_utils:hex_str_to_bin("0x" ++ binary_to_list(PL0)),
    CT = test_utils:hex_str_to_bin("0x" ++ binary_to_list(CT0)),
    {ok, CA1, CT1} = enoise_cipher_state:encrypt_with_ad(CA, <<>>, PL),
    ?assertEqual(CT, CT1),
    {ok, CA2, PL1} = enoise_cipher_state:decrypt_with_ad(CA, <<>>, CT1),
    ?assertEqual(CA1, CA2),
    ?assertEqual(PL, PL1),
    noise_test(Msgs, CB, CA1).
