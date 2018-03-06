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

-record(enoise, { pid }).

-type noise_options() :: [{atom(), term()}].
-opaque noise_socket() :: #enoise{}.

-export_type([noise_socket/0]).

%%====================================================================
%% API functions
%%====================================================================

%% @doc Upgrades a gen_tcp, or equivalent, connected socket to a Noise socket,
%% that is, performs the client-side noise handshake.
%% @end
-spec connect(TcpSock :: gen_tcp:socket(),
              Options :: noise_options()) ->
                    {ok, noise_socket()} | {error, term()}.
connect(TcpSock, Options) ->
    start_handshake(TcpSock, initiator, Options).

%% @doc Upgrades a gen_tcp, or equivalent, connected socket to a Noise socket,
%% that is, performs the server-side noise handshake.
%% @end
-spec accept(TcpSock :: gen_tcp:socket(),
             Options :: noise_options()) ->
                    {ok, noise_socket()} | {error, term()}.
accept(TcpSock, Options) ->
    start_handshake(TcpSock, responder, Options).

%% @doc Writes `Data` to `Socket`
%% @end
-spec send(Socket :: noise_socket(), Data :: binary()) -> ok | {error, term()}.
send(#enoise{ pid = Pid }, Data) ->
    enoise_connection:send(Pid, Data).

%% @doc Receives a packet from a socket in passive mode. A closed socket is
%% indicated by return value `{error, closed}`.
%%
%% Argument `Length` denotes the number of bytes to read. If Length = 0, all
%% available bytes are returned. If Length > 0, exactly Length bytes are
%% returned, or an error; possibly discarding less than Length bytes of data
%% when the socket gets closed from the other side.
%%
%% Optional argument `Timeout` specifies a time-out in milliseconds. The
%% default value is `infinity`.
%% @end
-spec recv(Socket :: noise_socket(), Length :: integer()) ->
        {ok, binary()} | {error, term()}.
recv(Socket, Length) ->
    recv(Socket, Length, infinity).

-spec recv(Socket :: noise_socket(), Length :: integer(),
           Timeout :: integer() | infinity) ->
        {ok, binary()} | {error, term()}.
recv(#enoise{ pid = Pid }, Length, Timeout) ->
    enoise_connection:recv(Pid, Length, Timeout).

%% @doc Closes a Noise connection.
%% @end
-spec close(NoiseSock :: noise_socket()) -> ok | {error, term()}.
close(#enoise{ pid = Pid }) ->
    enoise_connection:close(Pid).

%% @doc Assigns a new controlling process to the Noise socket. A controlling
%% process is the owner of an Noise socket, and receives all messages from the
%% socket.
%% @end
-spec controlling_process(Socket :: noise_socket(), Pid :: pid()) ->
        ok | {error, term()}.
controlling_process(#enoise{ pid = Pid }, NewPid) ->
    enoise_connection:controlling_process(Pid, NewPid).

%%====================================================================
%% Internal functions
%%====================================================================
start_handshake(TcpSock, Role, Options) ->
    case check_tcp(TcpSock) of
        {ok, WasActive} ->
            inet:setopts(TcpSock, [{active, false}]), %% False for handshake
            Prologue      = proplists:get_value(prologue, Options, <<>>),
            NoiseProtocol = proplists:get_value(noise, Options),

            S  = proplists:get_value(s, Options, undefined),
            E  = proplists:get_value(e, Options, undefined),
            RS = proplists:get_value(rs, Options, undefined),
            RE = proplists:get_value(re, Options, undefined),

            HSState = enoise_hs_state:init(NoiseProtocol, Role,
                                           Prologue, {S, E, RS, RE}),

            do_handshake(TcpSock, HSState, WasActive);
        Err = {error, _} ->
            Err
    end.

do_handshake(TcpSock, HState, WasActive) ->
    case enoise_hs_state:next_message(HState) of
        in ->
            case hs_recv(TcpSock) of
                {ok, Data} ->
                    {ok, HState1, _Msg} = enoise_hs_state:read_message(HState, Data),
                    do_handshake(TcpSock, HState1, WasActive);
                Err = {error, _} ->
                    Err
            end;
        out ->
            {ok, HState1, Msg} = enoise_hs_state:write_message(HState, <<>>),
            hs_send(TcpSock, Msg),
            do_handshake(TcpSock, HState1, WasActive);
        done ->
            {ok, #{ rx := Rx, tx := Tx }} = enoise_hs_state:finalize(HState),
            {ok, Pid} = enoise_connection:start_link(TcpSock, Rx, Tx, self(), WasActive),
            {ok, #enoise{ pid = Pid }}
    end.

check_tcp(TcpSock) ->
    {ok, TcpOpts} = inet:getopts(TcpSock, [mode, packet, active, header, packet_size]),
    Packet = proplists:get_value(packet, TcpOpts, 0),
    Header = proplists:get_value(header, TcpOpts, 0),
    Active = proplists:get_value(active, TcpOpts, true),
    PSize  = proplists:get_value(packet_size, TcpOpts, undefined),
    Mode   = proplists:get_value(mode, TcpOpts, binary),
    case (Packet == 0 orelse Packet == raw)
        andalso Header == 0 andalso PSize == 0 andalso Mode == binary of
        true ->
            case gen_tcp:controlling_process(TcpSock, self()) of
                ok               -> {ok, Active};
                Err = {error, _} -> Err
            end;
        false ->
            {error, {invalid_tcp_options, proplists:delete(active, TcpOpts)}}
    end.

hs_send(TcpSock, Msg) ->
    Len = byte_size(Msg),
    gen_tcp:send(TcpSock, <<Len:16, Msg/binary>>).

hs_recv(TcpSock) ->
    {ok, <<Len:16>>} = gen_tcp:recv(TcpSock, 2, 1000),
    gen_tcp:recv(TcpSock, Len, 1000).

