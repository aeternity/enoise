%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_crypto_tests).

-include_lib("eunit/include/eunit.hrl").

chachapoly_test() ->
    #{ key := Key, nonce := Nonce, ad := AD, mac := MAC,
       pt := PlainText, ct := CipherText } = test_utils:chacha_data(),
    PTLen  = byte_size(PlainText),
    CTLen  = byte_size(CipherText),
    MACLen = byte_size(MAC),

    %% Sanity check
    ?assert(PTLen == CTLen),

    <<CipherText0:CTLen/binary, MAC0:MACLen/binary>> =
        enoise_crypto:encrypt('ChaChaPoly', Key, Nonce, AD, PlainText),

    ?assertMatch(CipherText, CipherText0),
    ?assertMatch(MAC, MAC0),

    <<PlainText0:PTLen/binary>> =
        enoise_crypto:decrypt('ChaChaPoly', Key, Nonce, AD, <<CipherText/binary, MAC/binary>>),

    ?assertMatch(PlainText, PlainText0),
    ok.

