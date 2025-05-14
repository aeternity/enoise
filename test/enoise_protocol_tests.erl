%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_protocol_tests).

-include_lib("eunit/include/eunit.hrl").

name_test() ->
    roundtrip("Noise_XK_25519_ChaChaPoly_SHA512"),
    roundtrip("Noise_NN_25519_AESGCM_BLAKE2b"),
    roundtrip("Noise_NXpsk2_25519_AESGCM_SHA512").

name_pattern_test() ->
    Pat = "XKfallback+psk0",
    {Pat1, Mods1} = enoise_protocol:from_name_pattern(Pat),
    RoundPat = lists:flatten(enoise_protocol:to_name_pattern(Pat1, Mods1)),
    ?assertEqual(Pat, RoundPat).

roundtrip(Name) ->
    ExpectedName = iolist_to_binary(Name),
    ?assertMatch(ExpectedName, enoise_protocol:to_name(enoise_protocol:from_name(Name))).
