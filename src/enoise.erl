%%% ------------------------------------------------------------------
%%% @copyright 2018, Aeternity Anstalt
%%%
%%% @doc Module is an interface to the Noise protocol
%%% [https://noiseprotocol.org]
%%%
%%% The module implements Noise handshake in `handshake/3'.
%%%
%%% For convenience there is also an API to use Noise over TCP (i.e. `gen_tcp')
%%% and after "upgrading" a `gen_tcp'-socket into a `enoise'-socket it has a
%%% similar API as `gen_tcp'.
%%%
%%% @end ------------------------------------------------------------------

-module(enoise).

%% Main function with generic Noise handshake
-export([handshake/2, handshake/3, step_handshake/2]).

%% API exports - Mainly mimicing gen_tcp
-export([ accept/2
        , close/1
        , connect/2
        , controlling_process/2
        , recv/2
        , recv/3
        , send/2 ]).

-record(enoise, { pid }).

-type noise_key() :: binary().
-type noise_keypair() :: enoise_keypair:keypair().

-type noise_options() :: [noise_option()].
%% A list of Noise options is a proplist, it *must* contain a value `noise'
%% that describes which Noise configuration to use. It is possible to give a
%% `prologue' to the protocol. And for the protocol to work, the correct
%% configuration of pre-defined keys (`s', `e', `rs', `re') should also be
%% provided.

-type noise_option() :: {noise, noise_protocol_option()} %% Required
                      | {e, noise_keypair()} %% Mandatary depending on `noise'
                      | {s, noise_keypair()}
                      | {re, noise_key()}
                      | {rs, noise_key()}
                      | {prologue, binary()}. %% Optional

-type noise_protocol_option() :: enoise_protocol:protocol() | string() |
binary().
%% Either an instantiated Noise protocol configuration or the name of a Noise
%% configuration (either as a string or a binary string).

-opaque noise_socket() :: #enoise{}.
%% An abstract Noise socket - holds a reference to a socket that has completed
%% a Noise handshake.

-export_type([noise_socket/0]).

%%====================================================================
%% API functions
%%====================================================================

%% @doc Start an interactive handshake
handshake(Options, Role) ->
    HState = create_hstate(Options, Role),
    step_handshake(HState, <<>>).

step_handshake(HState, Data) ->
    do_step_handshake(HState, Data).

%% @doc The main function - performs a Noise handshake
handshake(Options, Role, ComState) ->
    HState = create_hstate(Options, Role),
    do_handshake(HState, ComState).


%% @doc Upgrades a gen_tcp, or equivalent, connected socket to a Noise socket,
%% that is, performs the client-side noise handshake.
%%
%% {@link noise_options()} is a proplist.
%% @end
-spec connect(TcpSock :: gen_tcp:socket(),
              Options :: noise_options()) ->
                    {ok, noise_socket()} | {error, term()}.
connect(TcpSock, Options) ->
    tcp_handshake(TcpSock, initiator, Options).

%% @doc Upgrades a gen_tcp, or equivalent, connected socket to a Noise socket,
%% that is, performs the server-side noise handshake.
%%
%% {@link noise_options()} is a proplist.
%% @end
-spec accept(TcpSock :: gen_tcp:socket(),
             Options :: noise_options()) ->
                    {ok, noise_socket()} | {error, term()}.
accept(TcpSock, Options) ->
    tcp_handshake(TcpSock, responder, Options).

%% @doc Writes `Data' to `Socket'
%% @end
-spec send(Socket :: noise_socket(), Data :: binary()) -> ok | {error, term()}.
send(#enoise{ pid = Pid }, Data) ->
    enoise_connection:send(Pid, Data).

%% @equiv recv(Socket, Length, infinity)
-spec recv(Socket :: noise_socket(), Length :: integer()) ->
        {ok, binary()} | {error, term()}.
recv(Socket, Length) ->
    recv(Socket, Length, infinity).

%% @doc Receives a packet from a socket in passive mode. A closed socket is
%% indicated by return value `{error, closed}'.
%%
%% Argument `Length' denotes the number of bytes to read. If Length = 0, all
%% available bytes are returned. If Length > 0, exactly Length bytes are
%% returned, or an error; possibly discarding less than Length bytes of data
%% when the socket gets closed from the other side.
%%
%% Optional argument `Timeout' specifies a time-out in milliseconds. The
%% default value is `infinity'.
%% @end
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
do_handshake(HState, ComState) ->
    case enoise_hs_state:next_message(HState) of
        in ->
            case hs_recv_msg(ComState) of
                {ok, Data, ComState1} ->
                    {ok, HState1, _Msg} = enoise_hs_state:read_message(HState, Data),
                    do_handshake(HState1, ComState1);
                Err = {error, _} ->
                    Err
            end;
        out ->
            {ok, HState1, Msg} = enoise_hs_state:write_message(HState, <<>>),
            {ok, ComState1} = hs_send_msg(ComState, Msg),
            do_handshake(HState1, ComState1);
        done ->
            {ok, Res} = enoise_hs_state:finalize(HState),
            {ok, Res, ComState}
    end.

hs_recv_msg(CS = #{ recv_msg := Recv, state := S }) ->
    case Recv(S) of
        {ok, Data, S1}   -> {ok, Data, CS#{ state := S1 }};
        Err = {error, _} -> Err
    end.

hs_send_msg(CS = #{ send_msg := Send, state := S }, Data) ->
    case Send(S, Data) of
        {ok, S1}         -> {ok, CS#{ state := S1 }};
        Err = {error, _} -> Err
    end.

do_step_handshake(HState, Data) ->
    case enoise_hs_state:next_message(HState) of
        in when Data == <<>> ->
            {in, HState};
        in ->
            {ok, HState1, _Msg} = enoise_hs_state:read_message(HState, Data), %% TODO: error handling
            do_step_handshake(HState1, <<>>);
        out ->
            {ok, HState1, Msg} = enoise_hs_state:write_message(HState, <<>>),
            {out, Msg, HState1};
        done ->
            {done, enoise_hs_state:finalize(HState)}
    end.

%% -- gen_tcp specific functions ---------------------------------------------
tcp_handshake(TcpSock, Role, Options) ->
    case check_gen_tcp(TcpSock) of
        ok ->
            {ok, [{active, Active}]} = inet:getopts(TcpSock, [active]),
            ComState = #{ recv_msg => fun gen_tcp_rcv_msg/1,
                          send_msg => fun gen_tcp_snd_msg/2,
                          state    => {TcpSock, Active, <<>>} },

            case handshake(Options, Role, ComState) of
                {ok, #{ rx := Rx, tx := Tx }, #{ state := {_, _, Buf} }} ->
                    {ok, Pid} = enoise_connection:start_link(TcpSock, Rx, Tx, self(), {Active, Buf}),
                    {ok, #enoise{ pid = Pid }};
                Err = {error, _} ->
                    Err
            end;
        Err = {error, _} ->
            Err
    end.

create_hstate(Options, Role) ->
    Prologue       = proplists:get_value(prologue, Options, <<>>),
    NoiseProtocol0 = proplists:get_value(noise, Options),

    NoiseProtocol =
        case NoiseProtocol0 of
            X when is_binary(X); is_list(X) ->
                enoise_protocol:from_name(X);
            _ -> NoiseProtocol0
        end,

    S  = proplists:get_value(s, Options, undefined),
    E  = proplists:get_value(e, Options, undefined),
    RS = proplists:get_value(rs, Options, undefined),
    RE = proplists:get_value(re, Options, undefined),

    enoise_hs_state:init(NoiseProtocol, Role,
                         Prologue, {S, E, RS, RE}).

check_gen_tcp(TcpSock) ->
    {ok, TcpOpts} = inet:getopts(TcpSock, [mode, packet, header, packet_size]),
    Packet = proplists:get_value(packet, TcpOpts, 0),
    Header = proplists:get_value(header, TcpOpts, 0),
    PSize  = proplists:get_value(packet_size, TcpOpts, undefined),
    Mode   = proplists:get_value(mode, TcpOpts, binary),
    case (Packet == 0 orelse Packet == raw)
        andalso Header == 0 andalso PSize == 0 andalso Mode == binary of
        true ->
            gen_tcp:controlling_process(TcpSock, self());
        false ->
            {error, {invalid_tcp_options, TcpOpts}}
    end.

gen_tcp_snd_msg(S = {TcpSock, _, _}, Msg) ->
    Len = byte_size(Msg),
    ok = gen_tcp:send(TcpSock, <<Len:16, Msg/binary>>),
    {ok, S}.

gen_tcp_rcv_msg({TcpSock, true, Buf}) ->
    receive {tcp, TcpSock, Data} ->
        case <<Buf/binary, Data/binary>> of
            Buf1 = <<Len:16, Rest/binary>> when byte_size(Rest) < Len ->
                gen_tcp_rcv_msg({TcpSock, true, Buf1});
            <<Len:16, Rest/binary>> ->
                <<Data1:Len/binary, Buf1/binary>> = Rest,
                {ok, Data1, {TcpSock, true, Buf1}}
        end
    after 1000 ->
        {error, timeout}
    end;
gen_tcp_rcv_msg(S = {TcpSock, false, <<>>}) ->
    {ok, <<Len:16>>} = gen_tcp:recv(TcpSock, 2, 1000),
    case gen_tcp:recv(TcpSock, Len, 1000) of
        {ok, Data}       -> {ok, Data, S};
        Err = {error, _} -> Err
    end.

