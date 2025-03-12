%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_tests).

-include_lib("eunit/include/eunit.hrl").

noise_interactive_test_() ->
    %% Test vectors from https://raw.githubusercontent.com/rweather/noise-c/master/tests/vector/noise-c-basic.txt
    {setup,
        fun() -> test_utils:noise_test_vectors() end,
        fun(_X) -> ok end,
        fun(Tests) ->
            [ {maps:get(protocol_name, T), fun() -> noise_interactive(T) end}
              || T <- test_utils:noise_test_filter(Tests) ]
        end
    }.

noise_interactive(V = #{ protocol_name := Name }) ->
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

    noise_interactive(Name, Protocol, Init, Resp, Messages, FixK(HandshakeHash)),

    ok.

noise_interactive(_Name, Protocol, Init, Resp, Messages, HSHash) ->
    DH = enoise_protocol:dh(Protocol),
    SecK = fun(undefined) -> undefined; (Sec) -> enoise_keypair:new(DH, Sec, undefined) end,

    HSInit = fun(#{ e := E, s := S, rs := RS, prologue := PL }, R) ->
                Opts = [{noise, Protocol}, {s, SecK(S)}, {e, SecK(E)}, {rs, RS}, {prologue, PL}],
                enoise:handshake(Opts, R)
             end,
    {ok, InitHS} = HSInit(Init, initiator),
    {ok, RespHS} = HSInit(Resp, responder),

    noise_interactive(Messages, InitHS, RespHS, HSHash).

noise_interactive([#{ payload := PL0, ciphertext := CT0 } | Msgs], SendHS, RecvHS, HSHash) ->
    PL = test_utils:hex_str_to_bin("0x" ++ binary_to_list(PL0)),
    CT = test_utils:hex_str_to_bin("0x" ++ binary_to_list(CT0)),
    case enoise_hs_state:next_message(SendHS) of
        out ->
            {ok, send, Message, SendHS1} = enoise:step_handshake(SendHS, {send, PL}),
            ?assertEqual(CT, Message),
            {ok, rcvd, PL1, RecvHS1} = enoise:step_handshake(RecvHS, {rcvd, Message}),
            ?assertEqual(PL, PL1),
            noise_interactive(Msgs, RecvHS1, SendHS1, HSHash);
        done ->
            {ok, done, #{ rx := RX1, tx := TX1, hs_hash := HSHash1 }} = enoise:step_handshake(SendHS, done),
            {ok, done, #{ rx := RX2, tx := TX2, hs_hash := HSHash2 }} = enoise:step_handshake(RecvHS, done),
            ?assertEqual(RX1, TX2), ?assertEqual(RX2, TX1),
            ?assertEqual(HSHash, HSHash1), ?assertEqual(HSHash, HSHash2)
    end.

noise_dh25519_test_() ->
    %% Test vectors from https://raw.githubusercontent.com/rweather/noise-c/master/tests/vector/noise-c-basic.txt
    {setup,
        fun() -> setup_dh25519() end,
        fun(_X) -> ok end,
        fun({Tests, SKP, CKP}) ->
            [ {T, fun() -> noise_test(T, SKP, CKP) end} || T <- Tests ]
        end
    }.

noise_monitor_test_() ->
    {setup,
        fun() -> setup_dh25519() end,
        fun(_X) -> ok end,
        fun({Tests, SKP, CKP}) ->
                [ {T, fun() -> noise_monitor_test(T, SKP, CKP) end} || T <- Tests ]
        end
    }.

setup_dh25519() ->
    %% Generate a static key-pair for Client and Server
    SrvKeyPair = enoise_keypair:new(dh25519),
    CliKeyPair = enoise_keypair:new(dh25519),

    #{ hs_pattern := Ps, hash := Hs, cipher := Cs } = enoise_protocol:supported(),
    Configurations = [ enoise_protocol:to_name(P, dh25519, C, H)
                       || P <- Ps, C <- Cs, H <- Hs ],
    %% Configurations = [ enoise_protocol:to_name(xk, dh25519, 'ChaChaPoly', blake2b) ],
    {Configurations, SrvKeyPair, CliKeyPair}.

noise_test(Conf, SKP, CKP) ->
    #{econn := EConn, echo_srv := EchoSrv} = noise_test_run(Conf, SKP, CKP),
    enoise:close(EConn),
    enoise_utils:echo_srv_stop(EchoSrv),
    ok.

noise_test_run(Conf, SKP, CKP) ->
    {Pid, MRef} = spawn_monitor_proxy(
                    fun() -> noise_test_run_(Conf, SKP, CKP) end),
    receive
        {Pid, #{} = Info} ->
            Info#{proxy => Pid, proxy_mref => MRef}
    after 5000 ->
            erlang:error(timeout)
    end.

spawn_monitor_proxy(F) ->
    Me = self(),
    spawn_monitor(fun() ->
                          MRef = erlang:monitor(process, Me),
                          Res = F(),
                          Me ! {self(), Res},
                          proxy_loop(Me, MRef)
                  end).

proxy_loop(Parent, MRef) ->
    receive
        {Parent, Ref, F} when is_function(F, 0) ->
            Parent ! {Ref, F()},
            proxy_loop(Parent, MRef);
        {'DOWN', MRef, process, Parent, _} ->
            done
    end.

proxy_exec(P, F) when is_function(F, 0) ->
    R = erlang:monitor(process, P),
    P ! {self(), R, F},
    receive
        {R, Res} ->
            Res;
        {'DOWN', R, _, _, Reason} ->
            erlang:error(Reason)
    after 5000 ->
            erlang:error(timeout)
    end.

noise_test_run_(Conf, SKP, CKP) ->
    Protocol = enoise_protocol:from_name(Conf),
    Port     = 4556,

    SrvOpts = [{echos, 2}, {cpub, enoise_keypair:pubkey(CKP)}],
    EchoSrv = enoise_utils:echo_srv_start(Port, Protocol, SKP, SrvOpts),

    {ok, TcpSock} = gen_tcp:connect("localhost", Port, [{active, once}, binary, {reuseaddr, true}], 100),

    Opts = [{noise, Protocol}, {s, CKP}] ++ [{rs, enoise_keypair:pubkey(SKP)} || enoise_utils:need_rs(initiator, Conf) ],
    {ok, EConn, _} = enoise:connect(TcpSock, Opts),

    ok = enoise:send(EConn, <<"Hello World!">>),
    receive
        {noise, _, <<"Hello World!">>} -> ok
    after 100 -> error(timeout) end,

    enoise:set_active(EConn, once),

    ok = enoise:send(EConn, <<"Goodbye!">>),
    receive
        {noise, _, <<"Goodbye!">>} -> ok
    after 100 -> error(timeout) end,
    #{ econn => EConn
     , tcp_sock => TcpSock
     , echo_srv => EchoSrv }.

noise_monitor_test(Conf, SKP, CKP) ->
    #{ econn := {enoise, EConnPid}
     , proxy := Proxy
     , tcp_sock := _TcpSock } = noise_test_run(Conf, SKP, CKP),
    try proxy_exec(Proxy, fun() -> exit(normal) end)
    catch
        error:normal ->
            receive after 100 ->
                            false = is_process_alive(EConnPid)
                    end
    end.

%% Talks to local echo-server (noise-c)
%% client_test() ->
%%     TestProtocol = enoise_protocol:from_name("Noise_XK_25519_ChaChaPoly_BLAKE2b"),
%%     ClientPrivKey = <<64,168,119,119,151,194,94,141,86,245,144,220,78,53,243,231,168,216,66,199,49,148,202,117,98,40,61,109,170,37,133,122>>,
%%     ClientPubKey  = <<115,39,86,77,44,85,192,176,202,11,4,6,194,144,127,123, 34,67,62,180,190,232,251,5,216,168,192,190,134,65,13,64>>,
%%     ServerPubKey  = <<112,91,141,253,183,66,217,102,211,40,13,249,238,51,77,114,163,159,32,1,162,219,76,106,89,164,34,71,149,2,103,59>>,

%%     {ok, TcpSock} = gen_tcp:connect("localhost", 7890, [{active, once}, binary, {reuseaddr, true}], 1000),
%%     gen_tcp:send(TcpSock, <<0,8,0,0,3>>), %% "Noise_XK_25519_ChaChaPoly_Blake2b"

%%     Opts = [ {noise, TestProtocol}
%%            , {s, enoise_keypair:new(dh25519, ClientPrivKey, ClientPubKey)}
%%            , {rs, enoise_keypair:new(dh25519, ServerPubKey)}
%%            , {prologue, <<0,8,0,0,3>>}],

%%     {ok, EConn} = enoise:connect(TcpSock, Opts),
%%     ok = enoise:send(EConn, <<"ok\n">>),
%%     receive
%%         {noise, EConn, <<"ok\n">>} -> ok
%%     after 1000 -> error(timeout) end,
%%     %% {ok, <<"ok\n">>} = enoise:recv(EConn, 3, 1000),
%%     enoise:close(EConn).


%% Expects a call-in from a local echo-client (noise-c)
%% server_test_() ->
%%     {timeout, 20, fun() ->
%%     TestProtocol = enoise_protocol:from_name("Noise_XK_25519_ChaChaPoly_Blake2b"),

%%     ServerPrivKey = <<200,81,196,192,228,196,182,200,181,83,169,255,242,54,99,113,8,49,129,92,225,220,99,50,93,96,253,250,116,196,137,103>>,
%%     ServerPubKey  = <<112,91,141,253,183,66,217,102,211,40,13,249,238,51,77,114,163,159,32,1,162,219,76,106,89,164,34,71,149,2,103,59>>,

%%     Opts = [ {noise, TestProtocol}
%%            , {s, enoise_keypair:new(dh25519, ServerPrivKey, ServerPubKey)}
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



