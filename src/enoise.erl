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
        , send/2
        , set_active/2 ]).

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
                      | {prologue, binary()} %% Optional
                      | {timeout, integer() | infinity}. %% Optional

-type noise_protocol_option() :: enoise_protocol:protocol() | string() |
binary().
%% Either an instantiated Noise protocol configuration or the name of a Noise
%% configuration (either as a string or a binary string).

-type com_state_state() :: term().
%% The state part of a communiction state

-type recv_msg_fun() :: fun((com_state_state(), integer() | infinity) ->
                            {ok, binary(), com_state_state()} | {error, term()}).
%% Function that receive a message

-type send_msg_fun() :: fun((com_state_state(), binary()) -> ok).
%% Function that sends a message

-type noise_com_state() :: #{ recv_msg := recv_msg_fun(),
                              send_msg := send_msg_fun(),
                              state    := term() }.
%% Noise communication state - used to parameterize a handshake. Consists of a
%% send function one receive function and an internal state.

-type noise_split_state() :: #{ rx := enoise_cipher_state:state(),
                                tx := enoise_cipher_state:state(),
                                hs_hash := binary() }.
%% Return value from the final `split' operation. Provides a CipherState for
%% receiving and a CipherState transmission. Also includes the final handshake
%% hash for channel binding.

-opaque noise_socket() :: #enoise{}.
%% An abstract Noise socket - holds a reference to a socket that has completed
%% a Noise handshake.

-export_type([noise_socket/0]).

%%====================================================================
%% API functions
%%====================================================================

%% @doc Start an interactive handshake
%% @end
-spec handshake(Options :: noise_options(),
                Role :: enoise_hs_state:noise_role()) ->
        {ok, enoise_hs_state:state()} | {error, term()}.
handshake(Options, Role) ->
    HState = create_hstate(Options, Role),
    {ok, HState}.

%% @doc Do a step (either `{send, Payload}', `{rcvd, EncryptedData}',
%% or `done')
%% @end
-spec step_handshake(HState :: enoise_hs_state:state(),
                     Data :: {rcvd, binary()} | {send, binary()}) ->
          {ok, send, binary(), enoise_hs_state:state()}
        | {ok, rcvd, binary(), enoise_hs_state:state()}
        | {ok, done, noise_split_state()}
        | {error, term()}.
step_handshake(HState, Data) ->
    do_step_handshake(HState, Data).

%% @doc Perform a Noise handshake
%% @end
-spec handshake(Options :: noise_options(),
                Role :: enoise_hs_state:noise_role(),
                ComState :: noise_com_state()) ->
        {ok, noise_split_state(), noise_com_state()} | {error, term()}.
handshake(Options, Role, ComState) ->
    HState = create_hstate(Options, Role),
    Timeout = proplists:get_value(timeout, Options, infinity),
    do_handshake(HState, ComState, Timeout).


%% @doc Upgrades a gen_tcp, or equivalent, connected socket to a Noise socket,
%% that is, performs the client-side noise handshake.
%%
%% Note: The TCP socket has to be in mode `{active, true}' or `{active, once}',
%% passive receive is not supported.
%%
%% {@link noise_options()} is a proplist.
%% @end
-spec connect(TcpSock :: gen_tcp:socket(),
              Options :: noise_options()) ->
                    {ok, noise_socket(), enoise_hs_state:state()} | {error, term()}.
connect(TcpSock, Options) ->
    tcp_handshake(TcpSock, initiator, Options).

%% @doc Upgrades a gen_tcp, or equivalent, connected socket to a Noise socket,
%% that is, performs the server-side noise handshake.
%%
%% Note: The TCP socket has to be in mode `{active, true}' or `{active, once}',
%% passive receive is not supported.
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

%% @doc Set the active option `true | once'. Note that `N' and `false' are
%% not valid options for a Noise socket.
%% @end
-spec set_active(Socket :: noise_socket(), Mode :: true | once) ->
            ok | {error, term()}.
set_active(#enoise{ pid = Pid }, ActiveMode) ->
    enoise_connection:set_active(Pid, ActiveMode).

%%====================================================================
%% Internal functions
%%====================================================================
do_handshake(HState, ComState, Timeout) ->
    case enoise_hs_state:next_message(HState) of
        in ->
            case hs_recv_msg(ComState, Timeout) of
                {ok, Data, ComState1} ->
                    case enoise_hs_state:read_message(HState, Data) of
                        {ok, HState1, _Msg} ->
                            do_handshake(HState1, ComState1, Timeout);
                        Err = {error, _} ->
                            Err
                    end;
                Err = {error, _} ->
                    Err
            end;
        out ->
            {ok, HState1, Msg} = enoise_hs_state:write_message(HState, <<>>),
            {ok, ComState1} = hs_send_msg(ComState, Msg),
            do_handshake(HState1, ComState1, Timeout);
        done ->
            {ok, Res} = enoise_hs_state:finalize(HState),
            {ok, Res, ComState}
    end.

hs_recv_msg(CS = #{ recv_msg := Recv, state := S }, Timeout) ->
    case Recv(S, Timeout) of
        {ok, Data, S1}   -> {ok, Data, CS#{ state := S1 }};
        Err = {error, _} -> Err
    end.

hs_send_msg(CS = #{ send_msg := Send, state := S }, Data) ->
    case Send(S, Data) of
        {ok, S1}         -> {ok, CS#{ state := S1 }};
        Err = {error, _} -> Err
    end.

do_step_handshake(HState, Data) ->
    case {enoise_hs_state:next_message(HState), Data} of
        {in, {rcvd, Encrypted}} ->
            case enoise_hs_state:read_message(HState, Encrypted) of
                {ok, HState1, Msg} ->
                    {ok, rcvd, Msg, HState1};
                Err = {error, _} ->
                    Err
            end;
        {out, {send, Payload}} ->
            {ok, HState1, Msg} = enoise_hs_state:write_message(HState, Payload),
            {ok, send, Msg, HState1};
        {done, done} ->
            {ok, Res} = enoise_hs_state:finalize(HState),
            {ok, done, Res};
        {Next, _} ->
            {error, {invalid_step, expected, Next, got, Data}}
    end.

%% -- gen_tcp specific functions ---------------------------------------------
tcp_handshake(TcpSock, Role, Options) ->
    case check_gen_tcp(TcpSock) of
        ok ->
            case inet:getopts(TcpSock, [active]) of
                {ok, [{active, Active}]} ->
                    do_tcp_handshake(Options, Role, TcpSock, Active);
                Err = {error, _} ->
                    Err
            end;
        Err = {error, _} ->
            Err
    end.

do_tcp_handshake(Options, Role, TcpSock, Active) ->
    ComState = #{ recv_msg => fun gen_tcp_rcv_msg/2,
                  send_msg => fun gen_tcp_snd_msg/2,
                  state    => {TcpSock, Active, <<>>} },
    case handshake(Options, Role, ComState) of
        {ok, #{ rx := Rx, tx := Tx, final_state := FState }, #{ state := {_, _, Buf} }} ->
            case enoise_connection:start_link(TcpSock, Rx, Tx, self(), {Active, Buf}) of
                {ok, Pid} -> {ok, #enoise{ pid = Pid }, FState};
                Err = {error, _} -> Err
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
    case inet:getopts(TcpSock, [mode, packet, active, header, packet_size]) of
        {ok, TcpOpts} ->
            Packet = proplists:get_value(packet, TcpOpts, 0),
            Active = proplists:get_value(active, TcpOpts, 0),
            Header = proplists:get_value(header, TcpOpts, 0),
            PSize  = proplists:get_value(packet_size, TcpOpts, undefined),
            Mode   = proplists:get_value(mode, TcpOpts, binary),
            case (Packet == 0 orelse Packet == raw)
                    andalso (Active == true orelse Active == once)
                    andalso Header == 0 andalso PSize == 0 andalso Mode == binary of
                true ->
                    gen_tcp:controlling_process(TcpSock, self());
                false ->
                    {error, {invalid_tcp_options, TcpOpts}}
            end;
        Err = {error, _} ->
            Err
    end.

gen_tcp_snd_msg(S = {TcpSock, _, _}, Msg) ->
    Len = byte_size(Msg),
    case gen_tcp:send(TcpSock, <<Len:16, Msg/binary>>) of
        ok               -> {ok, S};
        Err = {error, _} -> Err
    end.

gen_tcp_rcv_msg({TcpSock, Active, Buf}, Timeout) ->
    receive {tcp, TcpSock, Data} ->
        %% Immediately re-set {active, once}
        [ inet:setopts(TcpSock, [{active, once}]) || Active == once ],
        case <<Buf/binary, Data/binary>> of
            Buf1 = <<Len:16, Rest/binary>> when byte_size(Rest) < Len ->
                gen_tcp_rcv_msg({TcpSock, true, Buf1}, Timeout);
            <<Len:16, Rest/binary>> ->
                <<Data1:Len/binary, Buf1/binary>> = Rest,
                {ok, Data1, {TcpSock, true, Buf1}}
        end
    after Timeout ->
        {error, timeout}
    end.

