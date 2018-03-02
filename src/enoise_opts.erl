%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_opts).

-export([tcp_opts/1]).

tcp_opts(_Options) ->
    [{active, true}, binary, {reuseaddr, true}].
