%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_utils).

-compile([export_all, nowarn_export_all]).

echo_srv_start(Port, Protocol, SKP, Opts) ->
    Pid = spawn(fun() -> echo_srv(Port, Protocol, SKP, Opts) end),
    timer:sleep(10),
    Pid.

echo_srv_stop(Pid) ->
    erlang:exit(Pid, kill).

echo_srv(Port, Protocol, SKP, SrvOpts) ->
    TcpOpts  = [{active, true}, binary, {reuseaddr, true}],

    {ok, LSock} = gen_tcp:listen(Port, TcpOpts),
    {ok, TcpSock} = gen_tcp:accept(LSock, 500),

    Opts = [{noise, Protocol}, {s, SKP}] ++
           [{rs, proplists:get_value(cpub, SrvOpts)} || need_rs(responder, Protocol)],

    AcceptRes =
        try
            enoise:accept(TcpSock, Opts)
        catch _:R -> gen_tcp:close(TcpSock), {error, {R, erlang:get_stacktrace()}} end,

    gen_tcp:close(LSock),

    case AcceptRes of
        {ok, EConn, _}   -> echo_srv_loop(EConn, SrvOpts);
        Err = {error, _} -> srv_reply(Err, SrvOpts)
    end.

echo_srv_loop(EConn, SrvOpts) ->

    Recv =
        case proplists:get_value(mode, SrvOpts, passive) of
            passive ->
                fun() ->
                    receive {noise, EConn, Data} -> Data
                    after 200 -> error(timeout) end
                end;
            active  ->
                fun() ->
                    {ok, Msg} = enoise:recv(EConn, 0, 100),
                    Msg
                end
        end,

    Echos = proplists:get_value(echos, SrvOpts, 2),
    Res =
        try
            [ begin
                Msg = Recv(),
                ok = enoise:send(EConn, Msg)
            end || _ <- lists:seq(1, Echos) ],
            ok
        catch _:R -> {error, R} end,

    srv_reply(Res, SrvOpts),

    enoise:close(EConn),

    Res.

srv_reply(Reply, SrvOpts) ->
    case proplists:get_value(reply, SrvOpts, undefined) of
        undefined -> ok;
        Pid       -> Pid ! {self(), server_result, Reply}
    end.

need_rs(Role, Conf) when is_binary(Conf) ->
    need_rs(Role, enoise_protocol:from_name(Conf));
need_rs(Role, Protocol) ->
    PreMsgs = enoise_protocol:pre_msgs(Role, Protocol),
    lists:member({in, [s]}, PreMsgs).

