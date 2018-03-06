%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_protocol_tests).

-include_lib("eunit/include/eunit.hrl").

name_test() ->
    ?assertMatch(<<"Noise_XK_25519_ChaChaPoly_SHA512">>,
                 enoise_protocol:to_name(enoise_protocol:from_name("Noise_XK_25519_ChaChaPoly_SHA512"))).
