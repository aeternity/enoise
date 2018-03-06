%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_crypto_tests).

-include_lib("eunit/include/eunit.hrl").
-record(key_pair, { puk, pik }).

curve25519_test() ->
    KeyPair1 = enoise_crypto:new_key_pair(dh25519),
    KeyPair2 = enoise_crypto:new_key_pair(dh25519),

    SharedA = enoise_crypto:dh(dh25519, KeyPair1, KeyPair2#key_pair.puk),
    SharedB = enoise_crypto:dh(dh25519, KeyPair2, KeyPair1#key_pair.puk),
    ?assertMatch(SharedA, SharedB),

    #{ a_pub := APub, a_priv := APriv,
       b_pub := BPub, b_priv := BPriv, shared := Shared } = test_utils:curve25519_data(),

    ?assertMatch(Shared, enoise_crypto:dh(dh25519, #key_pair{ puk = APub, pik = APriv }, BPub)),
    ?assertMatch(Shared, enoise_crypto:dh(dh25519, #key_pair{ puk = BPub, pik = BPriv }, APub)),

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

