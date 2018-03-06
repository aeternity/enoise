%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_tests).

-include_lib("eunit/include/eunit.hrl").
-record(key_pair, { puk, pik }).


noise_test_() ->
    %% Test vector from https://raw.githubusercontent.com/rweather/noise-c/master/tests/vector/noise-c-basic.txt
    {setup,
        fun() -> test_utils:noise_test_vectors() end,
        fun(_X) -> ok end,
        fun(Tests) ->
            [ {maps:get(name, T), fun() -> noise_test(T) end} || T <- noise_test_filter(Tests) ]
        end
    }.

noise_test_filter(Tests0) ->
    Tests1 = [ T || T = #{ name := Name } <- Tests0, supported(Name) ],
    case length(Tests1) < length(Tests0) of
        true  -> ?debugFmt("WARNING: ~p test vectors are unsupported", [length(Tests0) - length(Tests1)]);
        false -> ok
    end,
    Tests1.

supported(Name) ->
    try enoise_protocol:from_name(Name), true
    catch _:_ -> false end.

noise_test(V = #{ name := Name }) ->
    %% ?debugFmt("~s", [Name]),
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
    PubK = fun(undefined) -> undefined; (S) -> enacl:curve25519_scalarmult_base(S) end,
    HSInit = fun(P, R, #{ e := E, s := S, rs := RS, prologue := PL }) ->
                enoise_hs_state:init(P, R, PL, {#key_pair{ pik = S, puk = PubK(S) },
                                                #key_pair{ pik = E, puk = PubK(E) },
                                                RS, undefined})
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
            {ok, RecvHS1, PL1} = enoise_hs_state:read_message(RecvHS, <<(byte_size(Message)):16, Message/binary>>),
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

%% Talks to local echo-server (noise-c)
client_test() ->
    TestProtocol = enoise_protocol:from_name("Noise_XK_25519_ChaChaPoly_BLAKE2b"),
    ClientPrivKey = <<64,168,119,119,151,194,94,141,86,245,144,220,78,53,243,231,168,216,66,199,49,148,202,117,98,40,61,109,170,37,133,122>>,
    ClientPubKey  = <<115,39,86,77,44,85,192,176,202,11,4,6,194,144,127,123, 34,67,62,180,190,232,251,5,216,168,192,190,134,65,13,64>>,
    ServerPubKey  = <<112,91,141,253,183,66,217,102,211,40,13,249,238,51,77,114,163,159,32,1,162,219,76,106,89,164,34,71,149,2,103,59>>,

    {ok, TcpSock} = gen_tcp:connect("localhost", 7890, [{active, true}, binary, {reuseaddr, true}], 1000),
    gen_tcp:send(TcpSock, <<0,8,0,0,3>>), %% "Noise_XK_25519_ChaChaPoly_Blake2b"

    Opts = [ {noise, TestProtocol}
           , {s, #key_pair{ pik = ClientPrivKey, puk = ClientPubKey }}
           , {rs, ServerPubKey}
           , {prologue, <<0,8,0,0,3>>}],

    {ok, EConn} = enoise:connect(TcpSock, Opts),
    EConn1 = enoise:send(EConn, <<"ok\n">>),
    {EConn2, <<"ok\n">>} = enoise:recv(EConn1),
    enoise:close(EConn2).


%% Expects a call-in from a local echo-client (noise-c)
%% server_test_() ->
%%     {timeout, 20, fun() ->
%%     TestProtocol = enoise_protocol:from_name("Noise_XK_25519_ChaChaPoly_Blake2b"),

%%     ServerPrivKey = <<200,81,196,192,228,196,182,200,181,83,169,255,242,54,99,113,8,49,129,92,225,220,99,50,93,96,253,250,116,196,137,103>>,
%%     ServerPubKey  = <<112,91,141,253,183,66,217,102,211,40,13,249,238,51,77,114,163,159,32,1,162,219,76,106,89,164,34,71,149,2,103,59>>,

%%     Opts = [ {noise, TestProtocol}
%%            , {s, #key_pair{ pik = ServerPrivKey, puk = ServerPubKey }}
%%            , {prologue, <<0,8,0,0,3>>}],

%%     {ok, LSock} = gen_tcp:listen(7891, [{reuseaddr, true}, binary]),

%%     {ok, TcpSock} = gen_tcp:accept(LSock, 10000),

%%     receive {tcp, TcpSock, <<0,8,0,0,3>>} -> ok
%%     after 1000 -> error(timeout) end,

%%     {ok, EConn} = enoise:accept(TcpSock, Opts),

%%     {EConn1, Msg} = enoise:recv(EConn),
%%     EConn2 = enoise:send(EConn1, Msg),

%%     enoise:close(EConn2)
%%     end}.



