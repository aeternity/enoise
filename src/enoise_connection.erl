%%% ------------------------------------------------------------------
%%% @copyright 2018, Aeternity Anstalt
%%%
%%% @doc Module implementing a gen_server for holding a handshaked
%%% Noise connection over gen_tcp.
%%%
%%% Some care is needed since the underlying transmission is broken up
%%% into Noise packets, so we need some buffering.
%%%
%%% @end
%%% ------------------------------------------------------------------

-module(enoise_connection).

-export([ controlling_process/2
        , close/1
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
start_link(TcpSock, Rx, Tx, Owner, {Active, Buf}) ->
    State0 = #state{ rx = Rx, tx = Tx, owner = Owner,
                     tcp_sock = TcpSock, active = Active },
    State = case Active of
                true  -> State0;
                false -> State0#state{ rawbuf = Buf }
            end,
    case gen_server:start_link(?MODULE, [State], []) of
        {ok, Pid} ->
            ok = gen_tcp:controlling_process(TcpSock, Pid),
            %% Changing controlling process if active requires a bit
            %% of fiddling with already received content...
            [ Pid ! {tcp, TcpSock, Buf} || Buf /= <<>>, Active ],
            flush_tcp(Active, Pid, TcpSock),
            {ok, Pid};
        Err = {error, _} ->
            Err
    end.

send(Noise, Data) ->
    gen_server:call(Noise, {send, Data}).

recv(Noise, Length, infinity) ->
    gen_server:call(Noise, {recv, Length, infinity}, infinity);
recv(Noise, Length, Timeout) ->
    gen_server:call(Noise, {recv, Length, Timeout}, Timeout + 100).

close(Noise) ->
    gen_server:call(Noise, close).

controlling_process(Noise, NewPid) ->
    gen_server:call(Noise, {controlling_process, self(), NewPid}, 100).

%% -- gen_server callbacks ---------------------------------------------------
init([State]) ->
    {ok, State}.

handle_call(close, _From, S) ->
    {stop, normal, ok, S};
handle_call(_Call, _From, S = #state{ tcp_sock = closed }) ->
    {reply, {error, closed}, S};
handle_call({send, Data}, _From, S) ->
    {Res, S1} = handle_send(S, Data),
    {reply, Res, S1};
handle_call({recv, _Length, _Timeout}, _From, S = #state{ active = true }) ->
    {reply, {error, active_socket}, S};
handle_call({recv, Length, Timeout}, _From, S) ->
    {Res, S1} = handle_recv(S, Length, Timeout),
    {reply, Res, S1};
handle_call({controlling_process, OldPid, NewPid}, _From, S) ->
    {Res, S1} = handle_control_change(S, OldPid, NewPid),
    {reply, Res, S1}.

handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info({tcp, TS, Data}, S = #state{ tcp_sock = TS }) ->
    {S1, Msgs} = handle_data(S, Data),
    S2 = handle_msgs(S1, Msgs),
    {noreply, S2};
handle_info({tcp_closed, TS}, S = #state{ tcp_sock = TS, active = A, owner = O }) ->
    [ O ! {tcp_closed, TS} || A ],
    {noreply, S#state{ tcp_sock = closed }};
handle_info(Msg, S) ->
    io:format("Unexpected info: ~p\n", [Msg]),
    {noreply, S}.

terminate(_Reason, #state{ tcp_sock = TcpSock }) ->
    [ gen_tcp:close(TcpSock) || TcpSock /= closed ],
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%% -- Local functions --------------------------------------------------------
handle_control_change(S = #state{ owner = Pid, tcp_sock = TcpSock }, Pid, NewPid) ->
    case gen_tcp:controlling_process(TcpSock, NewPid) of
        ok               -> {ok, S#state{ owner = NewPid }};
        Err = {error, _} -> {Err, S}
    end;
handle_control_change(S, _OldPid, _NewPid) ->
    {{error, not_owner}, S}.

handle_data(S = #state{ rawbuf = Buf, rx = Rx }, Data) ->
    case <<Buf/binary, Data/binary>> of
        B = <<Len:16, Rest/binary>> when Len > byte_size(Rest) ->
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

%% Some special cases
%% - Length = 0 (get all available data)
%%   This may leave raw (encrypted) data in rawbuf (but: buf = <<>>)
%% - Length N when there is stuff in rawbuf
handle_recv(S = #state{ buf = Buf, tcp_sock = TcpSock }, 0, TO) ->
    %% Get all available data
    {ok, Data} = gen_tcp:recv(TcpSock, 0, TO),
    %% Use handle_data to process it
    {S1, Msgs} = handle_data(S, Data),
    Res = lists:foldl(fun(Msg, B) -> <<B/binary, Msg/binary>> end, Buf, Msgs),
    {{ok, Res}, S1#state{ buf = <<>> }};
handle_recv(S = #state{ buf = Buf, rx = Rx }, Len, TO)
    when byte_size(Buf) < Len ->
    case recv_noise_msg(S, TO) of
        {ok, S1, Data} ->
            case enoise_cipher_state:decrypt_with_ad(Rx, <<>>, Data) of
                {ok, Rx1, Msg1} ->
                    NewBuf = <<Buf/binary, Msg1/binary>>,
                    handle_recv(S1#state{ buf = NewBuf, rx = Rx1 }, Len, TO);
                {error, _} ->
                    %% Return error and drop the data we could not decrypt
                    %% Unlikely that we can recover from this, but leave the
                    %% closing to the user...
                    {{error, decrypt_input_failed}, S1}
            end;
        {error, S1, Reason} ->
            {{error, Reason}, S1}
    end;
handle_recv(S = #state{ buf = Buf }, Len, _TO) ->
    <<Data:Len/binary, NewBuf/binary>> = Buf,
    {{ok, Data}, S#state{ buf = NewBuf }}.

%% A tad bit tricky, we need to be careful not to lose read data, and
%% also not spend (much) more than TO - while at the same time we can
%% have some previously received Raw data in rawbuf...
recv_noise_msg(S = #state{ rawbuf = RBuf, tcp_sock = TcpSock }, TO) ->
    case recv_noise_msg_len(TcpSock, RBuf, TO) of
        {error, Reason} ->
            {error, S, Reason};
        {ok, TimeSpent, RBuf1} ->
            TO1 = case TO of infinity -> infinity; _ -> TO - TimeSpent end,
            case recv_noise_msg_data(TcpSock, RBuf1, TO1) of
                {error, Reason} ->
                    {error, S#state{ rawbuf = RBuf1 }, Reason};
                {ok, Data} ->
                    {ok, S#state{rawbuf = <<>>}, Data}
            end
    end.

recv_noise_msg_len(TcpSock, <<>>, TO) ->
    timed_recv(TcpSock, 2, TO);
%% I wouldn't expect the following clause to ever be used
%% unless mocked tests are thrown at this!
recv_noise_msg_len(TcpSock, <<B0:8>>, TO) ->
    case timed_recv(TcpSock, 1, TO) of
        {ok, TimeSpent, <<B1:8>>} -> {ok, TimeSpent, <<B0:8, B1:8>>};
        Err = {error, _}          -> Err
    end;
recv_noise_msg_len(_, Buf, _) ->
    {ok, 0, Buf}.

recv_noise_msg_data(TcpSock, <<MsgLen:16, PreData/binary>>, TO) ->
    case gen_tcp:recv(TcpSock, MsgLen - byte_size(PreData), TO) of
        {ok, Data}       -> {ok, <<PreData/binary, Data/binary>>};
        Err = {error, _} -> Err
    end.

timed_recv(TcpSock, Len, TO) ->
    Start = erlang:timestamp(),
    case gen_tcp:recv(TcpSock, Len, TO) of
        {ok, Data} ->
            Diff = timer:now_diff(erlang:timestamp(), Start) div 1000,
            {ok, Diff, Data};
        Err = {error, _} ->
            Err
    end.

flush_tcp(false, _Pid, _TcpSock) ->
    ok;
flush_tcp(true, Pid, TcpSock) ->
    receive {tcp, TcpSock, Data} ->
        Pid ! {tcp, TcpSock, Data},
        flush_tcp(true, Pid, TcpSock)
    after 1 -> ok
    end.
