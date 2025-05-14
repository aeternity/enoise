%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------
-module(enoise_bad_data_tests).

-include_lib("eunit/include/eunit.hrl").

bad_data_hs_1_test() ->
    SrvKeyPair = enoise_keypair:new(dh25519),
    Proto      = enoise_protocol:to_name(xk, [], dh25519, 'ChaChaPoly', blake2b),
    Opts       = [{echos, 1}, {reply, self()}],
    Srv        = enoise_utils:echo_srv_start(4567, Proto, SrvKeyPair, Opts),

    bad_client(4567),

    SrvRes =
        receive {Srv, server_result, Res0} -> Res0
        after 500 -> timeout end,
    ?assertMatch({error, {bad_data, _}}, SrvRes),
    ok.

bad_client(Port) ->
    {ok, Sock} = gen_tcp:connect("localhost", Port, [binary, {reuseaddr, true}], 100),
    gen_tcp:send(Sock, <<0:256/unit:8>>),
    timer:sleep(100),
    gen_tcp:close(Sock).

