%%% ------------------------------------------------------------------
%%% @copyright 2018, Aeternity Anstalt
%%%
%%% @doc Module encapsulating a Noise handshake state
%%%
%%% @end
%%% ------------------------------------------------------------------

-module(enoise_hs_state).

-export([ finalize/1
        , init/4
        , next_message/1
        , read_message/2
        , remote_keys/1
        , write_message/2]).

-include("enoise.hrl").

-type noise_role()  :: initiator | responder.
-type noise_dh()    :: dh25519 | dh448.
-type noise_token() :: s | e | ee | ss | es | se.
-type keypair()     :: enoise_keypair:keypair().
-type noise_split_state() :: #{ rx := enoise_cipher_state:state(),
                                tx := enoise_cipher_state:state(),
                                hs_hash := binary(),
                                final_state => state() }.

-type optional_key() :: undefined | keypair().
-type initial_keys() :: {optional_key(), optional_key(), optional_key(), optional_key()}.

-record(noise_hs, { ss                :: enoise_sym_state:state()
                  , s                 :: keypair() | undefined
                  , e                 :: keypair() | undefined
                  , rs                :: keypair() | undefined
                  , re                :: keypair() | undefined
                  , role = initiator  :: noise_role()
                  , dh = dh25519      :: noise_dh()
                  , msgs = []         :: [enoise_protocol:noise_msg()] }).

-opaque state() :: #noise_hs{}.
-export_type([noise_dh/0, noise_role/0, noise_split_state/0, noise_token/0, state/0]).

-spec init(Protocol :: enoise_protocol:protocol(), Role :: noise_role(),
           Prologue :: binary(), Keys :: initial_keys()) -> {ok, state()} | {error, term()}.
init(Protocol, Role, Prologue, {S, E, RS, RE}) ->
    SS0 = enoise_sym_state:init(Protocol),
    SS1 = enoise_sym_state:mix_hash(SS0, Prologue),
    HS = #noise_hs{ ss = SS1
                  , s = S, e = E, rs = RS, re = RE
                  , role = Role
                  , dh = enoise_protocol:dh(Protocol)
                  , msgs = enoise_protocol:msgs(Role, Protocol) },
    PreMsgs = enoise_protocol:pre_msgs(Role, Protocol),
    pre_mix(PreMsgs, HS).

pre_mix([], HS) -> {ok, HS};
pre_mix([{out, [s]} | Msgs], HS = #noise_hs{ s = S }) when S /= undefined ->
    pre_mix(Msgs, mix_hash(HS, enoise_keypair:pubkey(S)));
pre_mix([{out, [e]} | Msgs], HS = #noise_hs{ e = E }) when E /= undefined ->
    pre_mix(Msgs, mix_hash(HS, enoise_keypair:pubkey(E)));
pre_mix([{in, [s]} | Msgs], HS = #noise_hs{ rs = RS }) when RS /= undefined ->
    pre_mix(Msgs, mix_hash(HS, enoise_keypair:pubkey(RS)));
pre_mix([{in, [e]} | Msgs], HS = #noise_hs{ re = RE }) when RE /= undefined ->
    pre_mix(Msgs, mix_hash(HS, enoise_keypair:pubkey(RE)));
pre_mix(_Msg, _HS) ->
    {error, invalid_noise_setup}.

-spec finalize(HS :: state()) -> {ok, noise_split_state()} | {error, term()}.
finalize(HS = #noise_hs{ msgs = [], ss = SS, role = Role }) ->
    {C1, C2} = enoise_sym_state:split(SS),
    HSHash   = enoise_sym_state:h(SS),
    Final    = #{ hs_hash => HSHash, final_state => HS },
    case Role of
        initiator -> {ok, Final#{ tx => C1, rx => C2 }};
        responder -> {ok, Final#{ rx => C1, tx => C2 }}
    end;
finalize(_) ->
    error({bad_state, finalize}).

-spec next_message(HS :: state()) -> in | out | done.
next_message(#noise_hs{ msgs = [{Dir, _} | _] }) -> Dir;
next_message(#noise_hs{ }) -> done.

-spec write_message(HS :: state(), PayLoad :: binary()) -> {ok, state(), binary()}.
write_message(HS = #noise_hs{ msgs = [{out, Msg} | Msgs] }, PayLoad) ->
    {HS1, MsgBuf1} = write_message(HS#noise_hs{ msgs = Msgs }, Msg, <<>>),
    {ok, HS2, MsgBuf2} = encrypt_and_hash(HS1, PayLoad),
    MsgBuf = <<MsgBuf1/binary, MsgBuf2/binary>>,
    {ok, HS2, MsgBuf}.

-spec read_message(HS :: state(), Message :: binary()) ->
        {ok, state(), binary()} | {error, term()}.
read_message(HS = #noise_hs{ msgs = [{in, Msg} | Msgs] }, Message) ->
    case read_message(HS#noise_hs{ msgs = Msgs }, Msg, Message) of
        {ok, HS1, RestBuf1}  -> decrypt_and_hash(HS1, RestBuf1);
        Err = {error, _} -> Err
    end.

-spec remote_keys(HS :: state()) -> undefined | keypair().
remote_keys(#noise_hs{ rs = RS }) ->
    RS.

write_message(HS, [], MsgBuf) ->
    {HS, MsgBuf};
write_message(HS, [Token | Tokens], MsgBuf0) ->
    {HS1, MsgBuf1} = write_token(HS, Token),
    write_message(HS1, Tokens, <<MsgBuf0/binary, MsgBuf1/binary>>).

read_message(HS, [], Data) ->
    {ok, HS, Data};
read_message(HS, [Token | Tokens], Data0) ->
    case read_token(HS, Token, Data0) of
        {ok, HS1, Data1} -> read_message(HS1, Tokens, Data1);
        Err = {error, _} -> Err
    end.

write_token(HS = #noise_hs{ e = undefined }, e) ->
    E = new_key_pair(HS),
    PubE = enoise_keypair:pubkey(E),
    {mix_hash(HS#noise_hs{ e = E }, PubE), PubE};
%% Should only apply during test - TODO: secure this
write_token(HS = #noise_hs{ e = E }, e) ->
    PubE = enoise_keypair:pubkey(E),
    {mix_hash(HS, PubE), PubE};
write_token(HS = #noise_hs{ s = S }, s) ->
    {ok, HS1, Msg} = encrypt_and_hash(HS, enoise_keypair:pubkey(S)),
    {HS1, Msg};
write_token(HS, Token) ->
    {K1, K2} = dh_token(HS, Token),
    {mix_key(HS, dh(HS, K1, K2)), <<>>}.

read_token(HS = #noise_hs{ re = undefined, dh = DH }, e, Data0) ->
    DHLen = enoise_crypto:dhlen(DH),
    case Data0 of
        <<REPub:DHLen/binary, Data1/binary>> ->
            RE = enoise_keypair:new(DH, REPub),
            {ok, mix_hash(HS#noise_hs{ re = RE }, REPub), Data1};
        _ ->
            {error, {bad_data, {failed_to_read_token, e, DHLen}}}
    end;
read_token(HS = #noise_hs{ rs = undefined, dh = DH }, s, Data0) ->
    DHLen = case has_key(HS) of
        true  -> enoise_crypto:dhlen(DH) + 16;
        false -> enoise_crypto:dhlen(DH)
    end,
    case Data0 of
        <<Temp:DHLen/binary, Data1/binary>> ->
            case decrypt_and_hash(HS, Temp) of
                {ok, HS1, RSPub} ->
                    RS = enoise_keypair:new(DH, RSPub),
                    {ok, HS1#noise_hs{ rs = RS }, Data1};
                Err = {error, _} ->
                    Err
            end;
        _ ->
            {error, {bad_data, {failed_to_read_token, s, DHLen}}}
    end;
read_token(HS, Token, Data) ->
    {K1, K2} = dh_token(HS, Token),
    {ok, mix_key(HS, dh(HS, K1, K2)), Data}.

dh_token(#noise_hs{ e = E, re = RE }                  , ee) -> {E, RE};
dh_token(#noise_hs{ e = E, rs = RS, role = initiator }, es) -> {E, RS};
dh_token(#noise_hs{ s = S, re = RE, role = responder }, es) -> {S, RE};
dh_token(#noise_hs{ s = S, re = RE, role = initiator }, se) -> {S, RE};
dh_token(#noise_hs{ e = E, rs = RS, role = responder }, se) -> {E, RS};
dh_token(#noise_hs{ s = S, rs = RS }                  , ss) -> {S, RS}.

%% Local wrappers
new_key_pair(#noise_hs{ dh = DH }) ->
    enoise_keypair:new(DH).

dh(#noise_hs{ dh = DH }, Key1, Key2) ->
    enoise_crypto:dh(DH, Key1, Key2).

has_key(#noise_hs{ ss = SS }) ->
    CS = enoise_sym_state:cipher_state(SS),
    enoise_cipher_state:has_key(CS).

mix_key(HS = #noise_hs{ ss = SS0 }, Data) ->
    HS#noise_hs{ ss = enoise_sym_state:mix_key(SS0, Data) }.

mix_hash(HS = #noise_hs{ ss = SS0 }, Data) ->
    HS#noise_hs{ ss = enoise_sym_state:mix_hash(SS0, Data) }.

encrypt_and_hash(HS = #noise_hs{ ss = SS0 }, PlainText) ->
    {ok, SS1, CipherText} = enoise_sym_state:encrypt_and_hash(SS0, PlainText),
    {ok, HS#noise_hs{ ss = SS1 }, CipherText}.

decrypt_and_hash(HS = #noise_hs{ ss = SS0 }, CipherText) ->
    case enoise_sym_state:decrypt_and_hash(SS0, CipherText) of
        {ok, SS1, PlainText} ->
            {ok, HS#noise_hs{ ss = SS1 }, PlainText};

        {error, Reason} ->
            {error, Reason}
    end.

