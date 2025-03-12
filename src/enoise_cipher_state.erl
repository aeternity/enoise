%%% ------------------------------------------------------------------
%%% @copyright 2018, Aeternity Anstalt
%%%
%%% @doc Module encapsulating a Noise Cipher state
%%%
%%% @end
%%% ------------------------------------------------------------------

-module(enoise_cipher_state).

-export([ cipher/1
        , decrypt_with_ad/3
        , encrypt_with_ad/3
        , has_key/1
        , init/2
        , key/1
        , rekey/1
        , set_key/2
        , set_nonce/2
        ]).

-include("enoise.hrl").

-type noise_cipher() :: 'ChaChaPoly' | 'AESGCM'.
-type nonce()        :: non_neg_integer().
-type key()          :: empty | binary().

-record(noise_cs, { k = empty             :: key()
                  , n = 0                 :: nonce()
                  , cipher = 'ChaChaPoly' :: noise_cipher() }).

-opaque state() :: #noise_cs{}.

-export_type([noise_cipher/0, state/0]).

-spec init(Key :: key(), Cipher :: noise_cipher()) -> state().
init(Key, Cipher) ->
    #noise_cs{ k = Key, n = 0, cipher = Cipher }.

-spec set_key(CState :: state(), NewKey :: key()) -> state().
set_key(CState, NewKey) ->
    CState#noise_cs{ k = NewKey, n = 0 }.

-spec has_key(CState :: state()) -> boolean().
has_key(#noise_cs{ k = Key }) ->
    Key =/= empty.

-spec set_nonce(CState :: state(), NewNonce :: nonce()) -> state().
set_nonce(CState = #noise_cs{}, Nonce) ->
    CState#noise_cs{ n = Nonce }.

-spec encrypt_with_ad(CState :: state(), AD :: binary(), PlainText :: binary()) ->
                {ok, state(), binary()} | {error, term()}.
encrypt_with_ad(CState = #noise_cs{ k = empty }, _AD, PlainText) ->
    {ok, CState, PlainText};
encrypt_with_ad(CState = #noise_cs{ k = K, n = N, cipher = Cipher }, AD, PlainText) ->
    CipherText = enoise_crypto:encrypt(Cipher, K, N, AD, PlainText),
    {ok, CState#noise_cs{ n = N+1 }, CipherText}.

-spec decrypt_with_ad(CState :: state(), AD :: binary(), CipherText :: binary()) ->
                {ok, state(), binary()} | {error, term()}.
decrypt_with_ad(CState = #noise_cs{ k = empty }, _AD, CipherText) ->
    {ok, CState, CipherText};
decrypt_with_ad(CState = #noise_cs{ k = K, n = N, cipher = Cipher }, AD, CipherText) ->
    case enoise_crypto:decrypt(Cipher, K, N, AD, CipherText) of
        PlainText when is_binary(PlainText) ->
            {ok, CState#noise_cs{ n = N+1 }, PlainText};
        Err = {error, _} ->
            Err
    end.

-spec rekey(CState :: state()) -> state().
rekey(CState = #noise_cs{ k = empty }) ->
    CState;
rekey(CState = #noise_cs{ k = K, cipher = Cipher }) ->
    CState#noise_cs{ k = enoise_crypto:rekey(Cipher, K) }.

-spec cipher(CState :: state()) -> noise_cipher().
cipher(#noise_cs{ cipher = Cipher }) ->
    Cipher.

-spec key(CState :: state()) -> key().
key(#noise_cs{ k = K }) ->
    K.
