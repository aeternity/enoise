%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_crypto_tests).

-include_lib("eunit/include/eunit.hrl").

curve25519_test() ->
    KeyPair1 = enoise_keypair:new(dh25519),
    KeyPair2 = enoise_keypair:new(dh25519),

    SharedA = enoise_crypto:dh(dh25519, KeyPair1, KeyPair2),
    SharedB = enoise_crypto:dh(dh25519, KeyPair2, KeyPair1),
    ?assertMatch(SharedA, SharedB),

    #{ a_pub := APub, a_priv := APriv,
       b_pub := BPub, b_priv := BPriv, shared := Shared } = test_utils:curve25519_data(),

    KeyPair3 = enoise_keypair:new(dh25519, APriv, APub),
    KeyPair4 = enoise_keypair:new(dh25519, BPriv, BPub),
    ?assertMatch(Shared, enoise_crypto:dh(dh25519, KeyPair3, KeyPair4)),
    ?assertMatch(Shared, enoise_crypto:dh(dh25519, KeyPair4, KeyPair3)),

    ok.

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

    Key1 = enoise_crypto:rekey('ChaChaPoly', Key),
    <<CipherText1:CTLen/binary, MAC1:MACLen/binary>> =
        enoise_crypto:encrypt('ChaChaPoly', Key1, Nonce, AD, PlainText),
    <<PlainText1:PTLen/binary>> =
        enoise_crypto:decrypt('ChaChaPoly', Key1, Nonce, AD, <<CipherText1/binary, MAC1/binary>>),
    ?assertMatch(PlainText, PlainText1),
    ok.

blake2b_test() ->
    Test = fun(#{ input := In, output := Out }) ->
               ?assertMatch(Out, enoise_crypto:hash(blake2b, In))
           end,
    lists:foreach(Test, test_utils:blake2b_data()).

%% blake2s_test() ->
%%     #{ input := In, output := Out } = test_utils:blake2s_data(),
%%     ?assertMatch(Out, enoise_crypto:hash(blake2s, In)).

blake2b_hmac_test() ->
    Test = fun(#{ key := Key, data := Data, hmac := HMAC }) ->
               ?assertMatch(HMAC, enoise_crypto:hmac(blake2b, Key, Data))
           end,
    lists:foreach(Test, test_utils:blake2b_hmac_data()).

blake2b_hkdf_test() ->
    Test = fun(#{ key := Key, data := Data, out1 := Out1, out2 := Out2 }) ->
               ?assertMatch([Out1, Out2, _], enoise_crypto:hkdf(blake2b, Key, Data))
           end,
    lists:foreach(Test, test_utils:blake2b_hkdf_data()).

