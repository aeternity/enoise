%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_protocol).

-export([ cipher/1
        , dh/1
        , from_name/1
        , hash/1
        , pattern/1
        , to_name/1]).

-type noise_pattern() :: nn | xk.

-record(noise_protocol,
        { hs_pattern = noiseNN      :: noise_pattern()
        , dh         = dh25519      :: enoise_hs_state:noise_dh()
        , cipher     = 'ChaChaPoly' :: enoise_cipher_state:noise_cipher()
        , hash       = blake2b      :: enoise_sym_state:noise_hash()
        }).

-opaque protocol() :: #noise_protocol{}.

-export_type([noise_pattern/0, protocol/0]).

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

to_name(_Protocol) ->
    <<"Noise_XK_25519_ChaChaPoly_BLAKE2b">>.

from_name("Noise_XK_25519_ChaChaPoly_Blake2b") ->
    #noise_protocol{ hs_pattern = xk, dh = dh25519, cipher = 'ChaChaPoly', hash = blake2b };
from_name(Name) ->
    error({protocol_not_implemented_yet, Name}).

