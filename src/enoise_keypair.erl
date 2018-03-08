%%% ------------------------------------------------------------------
%%% @copyright 2018, Aeternity Anstalt
%%%
%%% @doc Module is an abstract data type for a key pair.
%%%
%%% @end
%%% ------------------------------------------------------------------

-module(enoise_keypair).

-export([ key_type/1
        , new/1
        , new/2
        , new/3
        , pubkey/1
        , seckey/1
        ]).

-type key_type() :: dh25519 | dh448.

-record(kp, { type :: key_type()
            , sec  :: binary() | undefined
            , pub  :: binary() }).

-opaque keypair() :: #kp{}.
%% Abstract keypair holding a secret key/public key pair and its type.

-export_type([keypair/0]).

%% @doc Generate a new keypair of type `Type'.
-spec new(Type :: key_type()) -> keypair().
new(Type) ->
    {Sec, Pub} = new_key_pair(Type),
    #kp{ type = Type, sec = Sec, pub = Pub }.

%% @doc Create a new keypair of type `Type'. If `Public' is `undefined'
%% it will be computed from the `Secret' (using the curve/algorithm
%% indicated by `Type').
-spec new(Type :: key_type(), Secret :: binary(), Public :: binary() | undefined) -> keypair().
new(Type, Secret, undefined) ->
    new(Type, Secret, pubkey_from_secret(Type, Secret));
new(Type, Secret, Public) ->
    #kp{ type = Type, sec = Secret, pub = Public }.

%% @doc Define a "public only" keypair - holding just a public key and
%% `undefined' for secret key.
-spec new(Type :: key_type(), Public :: binary()) -> keypair().
new(Type, Public) ->
    #kp{ type = Type, sec = undefined, pub = Public }.

%% @doc Accessor function - return the key type of the key pair.
-spec key_type(KeyPair :: keypair()) -> key_type().
key_type(#kp{ type = T }) ->
    T.

%% @doc Accessor function - return the public key of the key pair.
-spec pubkey(KeyPair :: keypair()) -> binary().
pubkey(#kp{ pub = P }) ->
    P.

%% @doc Accessor function - return the secret key of the key pair.
%% This function will throw an error if the key pair is "public only".
-spec seckey(KeyPair :: keypair()) -> binary().
seckey(#kp{ sec = undefined }) ->
    error(keypair_is_public_only);
seckey(#kp{ sec = S }) ->
    S.

%% -- Local functions --------------------------------------------------------
new_key_pair(dh25519) ->
    KeyPair = enacl:crypto_sign_ed25519_keypair(),
    {enacl:crypto_sign_ed25519_secret_to_curve25519(maps:get(secret, KeyPair)),
     enacl:crypto_sign_ed25519_public_to_curve25519(maps:get(public, KeyPair))};
new_key_pair(Type) ->
    error({unsupported_key_type, Type}).

pubkey_from_secret(dh25519, Secret) ->
    enacl:curve25519_scalarmult_base(Secret).
