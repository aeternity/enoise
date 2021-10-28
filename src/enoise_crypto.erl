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
dh(dh25519, Key1, Key2) ->
    enacl:curve25519_scalarmult( enoise_keypair:seckey(Key1)
                               , enoise_keypair:pubkey(Key2));
dh(Type, _Key1, _Key2) ->
    error({unsupported_diffie_hellman, Type}).

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

-spec rekey(Cipher :: enoise_cipher_state:noise_cipher(),
            Key :: binary()) -> binary() | {error, term()}.
rekey('ChaChaPoly', K0) ->
    KLen = enacl:aead_chacha20poly1305_ietf_KEYBYTES(),
    <<K:KLen/binary, _/binary>> = encrypt('ChaChaPoly', K0, ?MAX_NONCE, <<>>, <<0:(32*8)>>),
    K;
rekey(Cipher, K) ->
    encrypt(Cipher, K, ?MAX_NONCE, <<>>, <<0:(32*8)>>).

-spec encrypt(Cipher :: enoise_cipher_state:noise_cipher(),
              Key :: binary(), Nonce :: non_neg_integer(),
              Ad :: binary(), PlainText :: binary()) ->
                binary() | {error, term()}.
encrypt('ChaChaPoly', K, N, Ad, PlainText) ->
    Nonce = <<0:32, N:64/little-unsigned-integer>>,
    enacl:aead_chacha20poly1305_ietf_encrypt(PlainText, Ad, Nonce, K);
encrypt('AESGCM', K, N, Ad, PlainText) ->
    Nonce = <<0:32, N:64>>,
    {CipherText, CipherTag} = crypto:block_encrypt(aes_gcm, K, Nonce, {Ad, PlainText}),
    <<CipherText/binary, CipherTag/binary>>.

-spec decrypt(Cipher ::enoise_cipher_state:noise_cipher(),
              Key :: binary(), Nonce :: non_neg_integer(),
              AD :: binary(), CipherText :: binary()) ->
                binary() | {error, term()}.
decrypt('ChaChaPoly', K, N, Ad, CipherText) ->
    Nonce = <<0:32, N:64/little-unsigned-integer>>,
    enacl:aead_chacha20poly1305_ietf_decrypt(CipherText, Ad, Nonce, K);
decrypt('AESGCM', K, N, Ad, CipherText0) ->
    CTLen = byte_size(CipherText0) - ?MAC_LEN,
    <<CipherText:CTLen/binary, MAC:?MAC_LEN/binary>> = CipherText0,
    Nonce = <<0:32, N:64>>,
    case crypto:block_decrypt(aes_gcm, K, Nonce, {Ad, CipherText, MAC}) of
        error -> {error, decrypt_failed};
        Data  -> Data
    end.


-spec hash(Hash :: enoise_sym_state:noise_hash(), Data :: binary()) -> binary().
hash(blake2b, Data) ->
    Hash = enacl:generichash(64, Data), Hash;
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

