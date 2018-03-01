%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_chiper_state_tests).

-include_lib("eunit/include/eunit.hrl").

chachapoly_test() ->
    #{ key := Key, nonce := Nonce, ad := AD, mac := MAC,
       pt := PlainText, ct := CipherText } = test_utils:chacha_data(),
    PTLen  = byte_size(PlainText),
    CTLen  = byte_size(CipherText),
    MACLen = byte_size(MAC),

    CS0 = enoise_cipher_state:init(Key, 'ChaChaPoly'),
    CS1 = enoise_cipher_state:set_nonce(CS0, Nonce),

    {ok, _CS2, <<CipherText0:CTLen/binary, MAC0:MACLen/binary>>} =
        enoise_cipher_state:encrypt_with_ad(CS1, AD, PlainText),

    ?assertMatch(CipherText, CipherText0),
    ?assertMatch(MAC, MAC0),

    {ok, _CS3, <<PlainText0:PTLen/binary>>} =
        enoise_cipher_state:decrypt_with_ad(CS1, AD, <<CipherText/binary, MAC/binary>>),

    ?assertMatch(PlainText, PlainText0),
    ok.

