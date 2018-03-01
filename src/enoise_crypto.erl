%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_crypto).

-include("enoise.hrl").

-export([decrypt/5, encrypt/5, rekey/2, hash/2, pad/3, hashlen/1, dhlen/1, new_key_pair/1, hkdf/3, dh/3]).

new_key_pair(dh25519) ->
    KeyPair = enacl:crypto_sign_ed25519_keypair(),
    #key_pair{ puk = enacl:crypto_sign_ed25519_public_to_curve25519(maps:get(public, KeyPair))
             , pik = enacl:crypto_sign_ed25519_secret_to_curve25519(maps:get(secret, KeyPair)) }.

dh(dh25519, KeyPair, PubKey) ->
    enacl:curve25519_scalarmult(KeyPair#key_pair.pik, PubKey).

hkdf(_, _, _) -> [].

rekey(Cipher, K) ->
    encrypt(Cipher, K, ?MAX_NONCE, <<>>, <<0:(32*8)>>).

encrypt('ChaChaPoly', K, N, Ad, PlainText) ->
    enacl:aead_chacha20poly1305_encrypt(K, N, Ad, PlainText).

-spec decrypt(Cipher ::enoise_cipher_state:noise_cipher(),
              Key :: binary(), Nonce :: non_neg_integer(),
              AD :: binary(), CipherText :: binary()) ->
                binary() | {error, term()}.
decrypt('ChaChaPoly', K, N, Ad, CipherText) ->
    enacl:aead_chacha20poly1305_decrypt(K, N, Ad, CipherText).

hash(blake2b, Data) ->
    enacl:generichash(64, Data);
hash(blake2s, Data) ->
    enacl:generichash(32, Data).

pad(Data, MinSize, PadByte) ->
    case byte_size(Data) of
        N when N >= MinSize ->
            Data;
        N ->
            PadData = << <<PadByte:8>> || _ <- lists:seq(1, MinSize - N) >>,
            <<Data/binary, PadData/binary>>
    end.

hashlen(sha256)  -> 32;
hashlen(sha512)  -> 64;
hashlen(blake2s) -> 32;
hashlen(blake2b) -> 64.

dhlen(dh25519) -> 32;
dhlen(dh448)   -> 56.
