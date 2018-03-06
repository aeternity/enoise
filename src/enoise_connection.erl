%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_connection).

-export([ close/1
        , recv/3
        , send/2
        , start_link/5
        ]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(enoise, { pid }).
-record(state, {rx, tx, owner, tcp_sock, active, buf = <<>>, rawbuf = <<>>}).

%% -- API --------------------------------------------------------------------
start_link(TcpSock, Rx, Tx, Owner, Active) ->
    inet:setopts(TcpSock, [{active, Active}]),
    State = #state{ rx = Rx, tx = Tx, owner = Owner,
                    tcp_sock = TcpSock, active = Active },
    case gen_server:start_link(?MODULE, [State], []) of
        {ok, Pid} ->
            ok = gen_tcp:controlling_process(TcpSock, Pid),
            {ok, Pid};
        Err = {error, _} ->
            Err
    end.

send(Noise, Data) ->
    gen_server:call(Noise, {send, Data}).

recv(Noise, Length, Timeout) ->
    gen_server:call(Noise, {recv, Length, Timeout}, Timeout + 100).

close(Noise) ->
    gen_server:call(Noise, close).

%% -- gen_server callbacks ---------------------------------------------------
init([State]) ->
    {ok, State}.

handle_call({send, Data}, _From, S) ->
    {Res, S1} = handle_send(S, Data),
    {reply, Res, S1};
handle_call({recv, _Length, _Timeout}, _From, S = #state{ active = true }) ->
    {reply, {error, active_socket}, S};
handle_call({recv, Length, Timeout}, _From, S) ->
    {Res, S1} = handle_recv(S, Length, Timeout),
    {reply, Res, S1};
handle_call(close, _From, S) ->
    {stop, normal, ok, S}.

handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info({tcp, TS, Data}, S = #state{ tcp_sock = TS }) ->
    {S1, Msgs} = handle_data(S, Data),
    S2 = handle_msgs(S1, Msgs),
    {noreply, S2};
handle_info({tcp_closed, TS}, S = #state{ tcp_sock = TS, active = A, owner = O }) ->
    [ O ! {tcp_closed, TS} || A ],
    {stop, tcp_closed, S};
handle_info(Msg, S) ->
    io:format("Unexpected info: ~p\n", [Msg]),
    {noreply, S}.

terminate(Reason, #state{ tcp_sock = TcpSock }) ->
    [ gen_tcp:close(TcpSock) || Reason /= tcp_closed ],
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%% -- Local functions --------------------------------------------------------
handle_data(S = #state{ rawbuf = Buf, rx = Rx }, Data) ->
    case <<Buf/binary, Data/binary>> of
        B = <<Len:16, Rest/binary>> when Len < byte_size(Rest) ->
            {S#state{ rawbuf = B }, []}; %% Not a full message - save it
        <<Len:16, Rest/binary>> ->
            <<Msg:Len/binary, Rest2/binary>> = Rest,
            case enoise_cipher_state:decrypt_with_ad(Rx, <<>>, Msg) of
                {ok, Rx1, Msg1} ->
                    {S1, Msgs} = handle_data(S#state{ rawbuf = Rest2, rx = Rx1 }, <<>>),
                    {S1, [Msg1 | Msgs]};
                {error, _} ->
                    error({enoise_error, decrypt_input_failed})
            end;
        EmptyOrSingleByte ->
            {S#state{ rawbuf = EmptyOrSingleByte }, []}
    end.

handle_msgs(S, []) ->
    S;
handle_msgs(S = #state{ active = true, owner = Owner, buf = <<>> }, Msgs) ->
    [ Owner ! {noise, #enoise{ pid = self() }, Msg} || Msg <- Msgs ],
    S;
handle_msgs(S = #state{ active = true, owner = Owner, buf = Buf }, Msgs) ->
    %% First send stuff in buffer (only when switching to active true)
    Owner ! {noise, #enoise{ pid = self() }, Buf},
    handle_msgs(S#state{ buf = <<>> }, Msgs);
handle_msgs(S = #state{ buf = Buf }, Msgs) ->
    NewBuf = lists:foldl(fun(Msg, B) -> <<B/binary, Msg/binary>> end, Buf, Msgs),
    S#state{ buf = NewBuf }.

handle_send(S = #state{ tcp_sock = TcpSock, tx = Tx }, Data) ->
    {ok, Tx1, Msg} = enoise_cipher_state:encrypt_with_ad(Tx, <<>>, Data),
    gen_tcp:send(TcpSock, <<(byte_size(Msg)):16, Msg/binary>>),
    {ok, S#state{ tx = Tx1 }}.

handle_recv(S = #state{ buf = Buf, rx = Rx, tcp_sock = TcpSock }, Len, TO)
    when byte_size(Buf) < Len ->
    {ok, <<MsgLen:16>>} = gen_tcp:recv(TcpSock, 2, TO),
    {ok, Data} = gen_tcp:recv(TcpSock, MsgLen, TO),
    case enoise_cipher_state:decrypt_with_ad(Rx, <<>>, Data) of
        {ok, Rx1, Msg1} ->
            handle_recv(S#state{ buf = <<Buf/binary, Msg1/binary>>, rx = Rx1 }, Len, TO);
        {error, _} ->
            error({enoise_error, decrypt_input_failed})
    end;
handle_recv(S = #state{ buf = Buf }, Len, _TO) ->
    <<Data:Len/binary, NewBuf/binary>> = Buf,
    {{ok, Data}, S#state{ buf = Buf }}.

