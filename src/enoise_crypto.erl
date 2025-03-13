%%% ------------------------------------------------------------------
%%% @copyright 2018, Aeternity Anstalt
%%%
%%% @doc Module implementing crypto primitives needed by Noise protocol
%%%
%%% @end
%%% ------------------------------------------------------------------

-module(enoise_crypto).

-include("enoise.hrl").

-export([ decrypt/5
        , dh/3
        , dhlen/1
        , encrypt/5
        , hash/2
        , hashlen/1
        , hkdf/3
        , hmac/3
        , pad/3
        , rekey/2
        ]).

-define(MAC_LEN, 16).

-type keypair() :: enoise_keypair:keypair().

%% @doc Perform a Diffie-Hellman calculation with the secret key from `Key1'
%% and the public key from `Key2' with algorithm `Algo'.
-spec dh(Algo :: enoise_hs_state:noise_dh(),
         Key1:: keypair(), Key2 :: keypair()) -> binary().
dh(Type, Key1, Key2) when Type == dh25519; Type == dh448 ->
    dh_(ecdh_type(Type), enoise_keypair:pubkey(Key2), enoise_keypair:seckey(Key1));
dh(Type, _Key1, _Key2) ->
    error({unsupported_diffie_hellman, Type}).

ecdh_type(dh25519) -> x25519;
ecdh_type(dh448)   -> x448.

dh_(DHType, OtherPub, MyPriv) ->
    crypto:compute_key(ecdh, OtherPub, MyPriv, DHType).

-spec hmac(Hash :: enoise_sym_state:noise_hash(),
           Key :: binary(), Data :: binary()) -> binary().
hmac(Hash, Key, Data) ->
    BLen = blocklen(Hash),
    Block1 = hmac_format_key(Hash, Key, 16#36, BLen),
    Hash1 = hash(Hash, <<Block1/binary, Data/binary>>),
    Block2 = hmac_format_key(Hash, Key, 16#5C, BLen),
    hash(Hash, <<Block2/binary, Hash1/binary>>).

-spec hkdf(Hash :: enoise_sym_state:noise_hash(),
           Key :: binary(), Data :: binary()) -> [binary()].
hkdf(Hash, Key, Data) ->
    TempKey = hmac(Hash, Key, Data),
    Output1 = hmac(Hash, TempKey, <<1:8>>),
    Output2 = hmac(Hash, TempKey, <<Output1/binary, 2:8>>),
    Output3 = hmac(Hash, TempKey, <<Output2/binary, 3:8>>),
    [Output1, Output2, Output3].

-spec rekey(Cipher :: enoise_cipher_state:noise_cipher(), Key :: binary()) -> binary().
rekey('ChaChaPoly', K0) ->
    KLen = 32,
    <<K:KLen/binary, _/binary>> = encrypt('ChaChaPoly', K0, ?MAX_NONCE, <<>>, <<0:(32*8)>>),
    K;
rekey(Cipher, K) ->
    encrypt(Cipher, K, ?MAX_NONCE, <<>>, <<0:(32*8)>>).

-spec encrypt(Cipher :: enoise_cipher_state:noise_cipher(), Key :: binary(),
              Nonce :: non_neg_integer(), Ad :: binary(), PlainText :: binary()) -> binary().
encrypt(Cipher, K, N, Ad, PlainText) ->
    {CText, CTag} = crypto:crypto_one_time_aead(cipher(Cipher), K, nonce(Cipher, N), PlainText, Ad, true),
    <<CText/binary, CTag/binary>>.

-spec decrypt(Cipher ::enoise_cipher_state:noise_cipher(), Key :: binary(),
              Nonce :: non_neg_integer(), AD :: binary(),
              CipherText :: binary()) -> binary() | {error, term()}.
decrypt(Cipher, K, N, Ad, CipherText0) ->
    CTLen = byte_size(CipherText0) - ?MAC_LEN,
    <<CText:CTLen/binary, MAC:?MAC_LEN/binary>> = CipherText0,
    case crypto:crypto_one_time_aead(cipher(Cipher), K, nonce(Cipher, N), CText, Ad, MAC, false) of
        error -> {error, decrypt_failed};
        Data  -> Data
    end.

nonce('ChaChaPoly', N) -> <<0:32, N:64/little-unsigned-integer>>;
nonce('AESGCM', N)     -> <<0:32, N:64/big-unsigned-integer>>.

cipher('ChaChaPoly') -> chacha20_poly1305;
cipher('AESGCM')     -> aes_256_gcm.

-spec hash(Hash :: enoise_sym_state:noise_hash(), Data :: binary()) -> binary().
hash(blake2s, Data) ->
    crypto:hash(blake2s, Data);
hash(blake2b, Data) ->
    crypto:hash(blake2b, Data);
hash(sha256, Data) ->
    crypto:hash(sha256, Data);
hash(sha512, Data) ->
    crypto:hash(sha512, Data);
hash(Hash, _Data) ->
    error({hash_not_implemented_yet, Hash}).

-spec pad(Data :: binary(), MinSize :: non_neg_integer(),
          PadByte :: integer()) -> binary().
pad(Data, MinSize, PadByte) ->
    case byte_size(Data) of
        N when N >= MinSize ->
            Data;
        N ->
            PadData = << <<PadByte:8>> || _ <- lists:seq(1, MinSize - N) >>,
            <<Data/binary, PadData/binary>>
    end.

-spec hashlen(Hash :: enoise_sym_state:noise_hash()) -> non_neg_integer().
hashlen(sha256)  -> 32;
hashlen(sha512)  -> 64;
hashlen(blake2s) -> 32;
hashlen(blake2b) -> 64.

-spec blocklen(Hash :: enoise_sym_state:noise_hash()) -> non_neg_integer().
blocklen(sha256)  -> 64;
blocklen(sha512)  -> 128;
blocklen(blake2s) -> 64;
blocklen(blake2b) -> 128.

-spec dhlen(DH :: enoise_hs_state:noise_dh()) -> non_neg_integer().
dhlen(dh25519) -> 32;
dhlen(dh448)   -> 56.

%%% Local implementations


hmac_format_key(Hash, Key0, Pad, BLen) ->
    Key1 =
        case byte_size(Key0) =< BLen of
            true  -> Key0;
            false -> hash(Hash, Key0)
        end,
    Key2 = pad(Key1, BLen, 0),
    <<PadWord:32>> = <<Pad:8, Pad:8, Pad:8, Pad:8>>,
    << <<(Word bxor PadWord):32>> || <<Word:32>> <= Key2 >>.

