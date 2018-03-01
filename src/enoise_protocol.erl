%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_protocol).

-include("enoise.hrl").

-export([to_name/1]).

to_name(_Protocol) ->
    <<"Noise_XK_25519_ChaChaPoly_BLAKE2b">>.
