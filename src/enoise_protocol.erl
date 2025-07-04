%%% ------------------------------------------------------------------
%%% @copyright 2018, Aeternity Anstalt
%%%
%%% @doc Module defining Noise protocol configurations
%%%
%%% @end
%%% ------------------------------------------------------------------

-module(enoise_protocol).

-export([ cipher/1
        , dh/1
        , from_name/1
        , hash/1
        , msgs/2
        , pattern/1
        , pre_msgs/2
        , supported/0
        , to_name/1]).

-ifdef(TEST).
-compile([export_all, nowarn_export_all]).
-endif.

-type noise_pattern() :: n | k | x | nn | nk | nk1 | nx | nx1 | xn | x1n | xk
                       | x1k | xk1 | x1k1 | xx | x1x | xx1 | x1x1 | kn | k1n
                       | kk | k1k | kk1 | k1k1 | kx | k1x | kx1 | k1x1
                       | in | i1n | ik | i1k | ik1 | i1k1 | ix | i1x | ix1 | i1x1.

-type noise_msg() :: {in | out, [enoise_hs_state:noise_token()]}.

-record(noise_protocol,
        { hs_pattern = nn           :: noise_pattern()
        , dh         = dh25519      :: enoise_hs_state:noise_dh()
        , cipher     = 'ChaChaPoly' :: enoise_cipher_state:noise_cipher()
        , hash       = blake2b      :: enoise_sym_state:noise_hash()
        }).

-opaque protocol() :: #noise_protocol{}.

-export_type([noise_msg/0, noise_pattern/0, protocol/0]).

-spec cipher(Protocol :: protocol()) -> enoise_cipher_state:noise_cipher().
cipher(#noise_protocol{ cipher = Cipher }) ->
    Cipher.

-spec dh(Protocol :: protocol()) -> enoise_hs_state:noise_dh().
dh(#noise_protocol{ dh = Dh }) ->
    Dh.

-spec hash(Protocol :: protocol()) -> enoise_sym_state:noise_hash().
hash(#noise_protocol{ hash = Hash }) ->
    Hash.

-spec pattern(Protocol :: protocol()) -> noise_pattern().
pattern(#noise_protocol{ hs_pattern = Pattern }) ->
    Pattern.

-spec to_name(Protocol :: protocol()) -> binary().
to_name(Protocol = #noise_protocol{ hs_pattern = Pattern, dh = Dh
                                  , cipher = Cipher, hash = Hash }) ->
    case supported_pattern(Pattern) andalso supported_dh(Dh) andalso
        supported_cipher(Cipher) andalso supported_hash(Hash) of
        true  -> to_name(Pattern, Dh, Cipher, Hash);
        false -> error({protocol_not_recognized, Protocol})
    end.

-spec from_name(Name :: string() | binary()) -> protocol().
from_name(Bin) when is_binary(Bin) -> from_name(binary_to_list(Bin));
from_name(String) ->
    case string:lexemes(String, "_") of
        ["Noise", PatStr, DhStr, CipStr, HashStr] ->
            Pattern = from_name_pattern(PatStr),
            Dh      = from_name_dh(DhStr),
            Cipher  = from_name_cipher(CipStr),
            Hash    = from_name_hash(HashStr),
            case supported_pattern(Pattern) andalso supported_dh(Dh) andalso
                supported_cipher(Cipher) andalso supported_hash(Hash) of
                true  -> #noise_protocol{ hs_pattern = Pattern, dh = Dh
                                        , cipher = Cipher, hash = Hash };
                false -> error({unsupported_protocol, String})
            end;
        _ ->
            error({unsupported_protocol, String})
    end.

-spec msgs(Role :: enoise_hs_state:noise_role(), Protocol :: protocol()) -> [noise_msg()].
msgs(Role, #noise_protocol{ hs_pattern = Pattern }) ->
    {_Pre, Msgs} = protocol(Pattern),
    role_adapt(Role, Msgs).

-spec pre_msgs(Role :: enoise_hs_state:noise_role(), Protocol :: protocol()) -> [noise_msg()].
pre_msgs(Role, #noise_protocol{ hs_pattern = Pattern }) ->
    {PreMsgs, _Msgs} = protocol(Pattern),
    role_adapt(Role, PreMsgs).

-spec role_adapt(Role :: enoise_hs_state:noise_role(), [noise_msg()]) -> [noise_msg()].
role_adapt(initiator, Msgs) ->
    Msgs;
role_adapt(responder, Msgs) ->
    Flip = fun({in, Msg}) -> {out, Msg}; ({out, Msg}) -> {in, Msg} end,
    lists:map(Flip, Msgs).

-spec protocol(Pattern :: noise_pattern()) -> {[noise_msg()], [noise_msg()]}.
protocol(n) -> {[{in, [s]}], [{out, [e, es]}]};
protocol(k) -> {[{out, [s]}, {in, [s]}], [{out, [e, es, ss]}]};
protocol(x) -> {[{in, [s]}], [{out, [e, es, s, ss]}]};

protocol(nn) -> {[], [{out, [e]}, {in, [e, ee]}]};

protocol(nk)  -> {[{in, [s]}], [{out, [e, es]}, {in, [e, ee]}]};
protocol(nk1) -> {[{in, [s]}], [{out, [e]}, {in, [e, ee, es]}]};

protocol(nx)  -> {[], [{out, [e]}, {in, [e, ee, s, es]}]};
protocol(nx1) -> {[], [{out, [e]}, {in, [e, ee, s]}, {out, [es]}]};

protocol(xn)  -> {[], [{out, [e]}, {in, [e, ee]}, {out, [s, se]}]};
protocol(x1n) -> {[], [{out, [e]}, {in, [e, ee]}, {out, [s]}, {in, [se]}]};

protocol(xk)   -> {[{in, [s]}], [{out, [e, es]}, {in, [e, ee]}, {out, [s, se]}]};
protocol(x1k)  -> {[{in, [s]}], [{out, [e, es]}, {in, [e, ee]}, {out, [s]}, {in, [se]}]};
protocol(xk1)  -> {[{in, [s]}], [{out, [e]}, {in, [e, ee, es]}, {out, [s, se]}]};
protocol(x1k1) -> {[{in, [s]}], [{out, [e]}, {in, [e, ee, es]}, {out, [s]}, {in, [se]}]};

protocol(xx)   -> {[], [{out, [e]}, {in, [e, ee, s, es]}, {out, [s, se]}]};
protocol(x1x)  -> {[], [{out, [e]}, {in, [e, ee, s, es]}, {out, [s]}, {in, [se]}]};
protocol(xx1)  -> {[], [{out, [e]}, {in, [e, ee, s]}, {out, [es, s, se]}]};
protocol(x1x1) -> {[], [{out, [e]}, {in, [e, ee, s]}, {out, [es, s]}, {in, [se]}]};

protocol(kn)  -> {[{out, [s]}], [{out, [e]}, {in, [e, ee, se]}]};
protocol(k1n) -> {[{out, [s]}], [{out, [e]}, {in, [e, ee]}, {out, [se]}]};

protocol(kk)   -> {[{out, [s]}, {in, [s]}], [{out, [e, es, ss]}, {in, [e, ee, se]}]};
protocol(k1k)  -> {[{out, [s]}, {in, [s]}], [{out, [e, es]}, {in, [e, ee]}, {out, [se]}]};
protocol(kk1)  -> {[{out, [s]}, {in, [s]}], [{out, [e]}, {in, [e, ee, se, es]}]};
protocol(k1k1) -> {[{out, [s]}, {in, [s]}], [{out, [e]}, {in, [e, ee, es]}, {out, [se]}]};

protocol(kx)   -> {[{out, [s]}], [{out, [e]}, {in, [e, ee, se, s, es]}]};
protocol(k1x)  -> {[{out, [s]}], [{out, [e]}, {in, [e, ee, s, es]}, {out, [se]}]};
protocol(kx1)  -> {[{out, [s]}], [{out, [e]}, {in, [e, ee, se, s]}, {out, [es]}]};
protocol(k1x1) -> {[{out, [s]}], [{out, [e]}, {in, [e, ee, s]}, {out, [se, es]}]};

protocol(in)  -> {[], [{out, [e, s]}, {in, [e, ee, se]}]};
protocol(i1n) -> {[], [{out, [e, s]}, {in, [e, ee]}, {out, [se]}]};

protocol(ik)   -> {[{in, [s]}], [{out, [e, es, s, ss]}, {in, [e, ee, se]}]};
protocol(i1k)  -> {[{in, [s]}], [{out, [e, es, s]}, {in, [e, ee]}, {out, [se]}]};
protocol(ik1)  -> {[{in, [s]}], [{out, [e, s]}, {in, [e, ee, se, es]}]};
protocol(i1k1) -> {[{in, [s]}], [{out, [e, s]}, {in, [e, ee, es]}, {out, [se]}]};

protocol(ix)   -> {[], [{out, [e, s]}, {in, [e, ee, se, s, es]}]};
protocol(i1x)  -> {[], [{out, [e, s]}, {in, [e, ee, s, es]}, {out, [se]}]};
protocol(ix1)  -> {[], [{out, [e, s]}, {in, [e, ee, se, s]}, {out, [es]}]};
protocol(i1x1) -> {[], [{out, [e, s]}, {in, [e, ee, s]}, {out, [se, es]}]}.

supported_pattern(P) ->
    lists:member(P, maps:get(hs_pattern, supported())).

supported_hash(Hash) ->
    lists:member(Hash, maps:get(hash, supported())).

supported_cipher(Cipher) ->
    lists:member(Cipher, maps:get(cipher, supported())).

supported_dh(Dh) ->
    lists:member(Dh, maps:get(dh, supported())).

-spec supported() -> map().
supported() ->
    #{ hs_pattern => [ n, k, x
                     , nn
                     , nk, nk1
                     , nx, nx1
                     , xn, x1n
                     , xk, x1k, xk1, x1k1
                     , xx, x1x, xx1, x1x1
                     , kn, k1n
                     , kk, k1k, kk1, k1k1
                     , kx, k1x, kx1, k1x1
                     , in, i1n
                     , ik, i1k, ik1, i1k1
                     , ix, i1x, ix1, i1x1
                     ]
     , hash       => [blake2s, blake2b, sha256, sha512]
     , cipher     => ['ChaChaPoly', 'AESGCM']
     , dh         => [dh25519, dh448]
     }.

to_name(Pattern, Dh, Cipher, Hash) ->
    list_to_binary(lists:join("_", ["Noise", to_name_pattern(Pattern), to_name_dh(Dh),
                                    to_name_cipher(Cipher), to_name_hash(Hash)])).

to_name_pattern(Atom) ->
    [Simple | Rest] = string:lexemes(atom_to_list(Atom), "_"),
    lists:flatten(string:uppercase(Simple) ++ lists:join("+", Rest)).

from_name_pattern(String) ->
    [Init | Mod2] = string:lexemes(String, "+"),
    {Simple, Mod1} = lists:splitwith(fun(C) -> (C >= $A andalso C =< $Z) orelse
                                               (C >= $0 andalso C =< $9) end, Init),
    list_to_atom(lists:flatten(string:lowercase(Simple) ++
        case Mod1 of
            "" -> "";
            _  -> "_" ++ lists:join("_", [Mod1 | Mod2])
        end)).

to_name_dh(dh25519) -> "25519";
to_name_dh(dh448)   -> "448".

from_name_dh(Dh) -> list_to_atom("dh" ++ Dh).

to_name_cipher(Cipher) -> atom_to_list(Cipher).

from_name_cipher(Cipher) -> list_to_atom(Cipher).

to_name_hash(sha256)  -> "SHA256";
to_name_hash(sha512)  -> "SHA512";
to_name_hash(blake2s) -> "BLAKE2s";
to_name_hash(blake2b) -> "BLAKE2b".

from_name_hash(Hash) -> list_to_atom(string:lowercase(Hash)).
