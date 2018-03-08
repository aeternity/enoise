%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_sym_state_tests).

-include_lib("eunit/include/eunit.hrl").

noise_XK_25519_ChaChaPoly_Blake2b_test() ->
    Protocol =  enoise_protocol:from_name("Noise_XK_25519_ChaChaPoly_BLAKE2b"),

    SSE0 = enoise_sym_state:init(Protocol),
    SSD0 = enoise_sym_state:init(Protocol),

    Name = enoise_protocol:to_name(Protocol),
    PadName = enoise_crypto:pad(Name, enoise_crypto:hashlen(blake2b), 0),

    ?assertMatch(PadName, enoise_sym_state:h(SSE0)),
    ?assertMatch(PadName, enoise_sym_state:ck(SSE0)),
    ?assertMatch(false, enoise_cipher_state:has_key(enoise_sym_state:cipher_state(SSE0))),

    TestBin = h2b("0x6162636465666768696A6B6C6D6E6F707172737475767778797A"),
    SSE1 = enoise_sym_state:mix_hash(SSE0, TestBin),
    SSD1 = enoise_sym_state:mix_hash(SSD0, TestBin),

    ExpHash1 = enoise_crypto:hash(blake2b, <<PadName/binary, TestBin/binary>>),
    ExpHash2 = h2b("0x8DC23DE176F6B3581FB7E18F258A47B1E1A8090BF55978868F1AC88C672DC3918FA4D1828338FB5DF652F5C33D57C79537CB5D074057EF59C346D0B35A160F71"),
    ?assertMatch(ExpHash1, enoise_sym_state:h(SSE1)),
    ?assertMatch(ExpHash2, enoise_sym_state:h(SSD1)),

    {ok, SSE2, TestBin} = enoise_sym_state:encrypt_and_hash(SSE1, TestBin),
    {ok, SSD2, TestBin} = enoise_sym_state:decrypt_and_hash(SSD1, TestBin),

    SSE3 = enoise_sym_state:mix_key(SSE2, TestBin),
    SSD3 = enoise_sym_state:mix_key(SSD2, TestBin),

    ExpEncrypt = h2b("0x24FB13758E6BA9901A4CEA117AE1D9AF757B02CAE96EFDFDA5ED3927BDD9FEA0239F7F673E924AAE81E6"),
    {ok, SSE4, Encrypt} = enoise_sym_state:encrypt_and_hash(SSE3, TestBin),
    ?assertMatch(ExpEncrypt, Encrypt),
    {ok, SSD4, Decrypt} = enoise_sym_state:decrypt_and_hash(SSD3, ExpEncrypt),
    ?assertMatch(TestBin, Decrypt),

    Key1 = h2b("0x893FD190EDB611D9AF73868C8AB020F7A13C62F70F7F74C46859CF4A1E71BB74"),
    Key2 = h2b("0x492E210AD0181CE70BF9CE80308DE45EAE1FA76E1ACE22A829EF6F1A01C6E2C8"),

    {CSE1, CSE2} = enoise_sym_state:split(SSE4),
    ?assertMatch(Key1, enoise_cipher_state:key(CSE1)),
    ?assertMatch(Key2, enoise_cipher_state:key(CSE2)),

    {CSD1, CSD2} = enoise_sym_state:split(SSD4),
    ?assertMatch(Key1, enoise_cipher_state:key(CSD1)),
    ?assertMatch(Key2, enoise_cipher_state:key(CSD2)),

    ok.

h2b(S) -> test_utils:hex_str_to_bin(S).
