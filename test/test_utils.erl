%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(test_utils).
-include_lib("eunit/include/eunit.hrl").

-compile([export_all, nowarn_export_all]).

%% -- Test data --------------------------------------------------------------
curve25519_data() ->
    #{ a_priv => hex_str_to_bin("0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
       a_pub  => hex_str_to_bin("0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
       b_priv => hex_str_to_bin("0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
       b_pub  => hex_str_to_bin("0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
       shared => hex_str_to_bin("0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
     }.

chacha_data() ->
    #{ key   => hex_str_to_bin("0x1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
     , nonce => 16#0807060504030201
     , ad    => hex_str_to_bin("0xf33388860000000000004e91")
     , pt    => hex_str_to_bin("0x496e7465726e65742d4472616674732061726520647261667420646f63756d65"
           "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d"
           "6f6e74687320616e64206d617920626520757064617465642c207265706c6163"
           "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65"
           "6e747320617420616e792074696d652e20497420697320696e617070726f7072"
           "6961746520746f2075736520496e7465726e65742d4472616674732061732072"
           "65666572656e6365206d6174657269616c206f7220746f206369746520746865"
           "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67"
           "726573732e2fe2809d")
     , ct    => hex_str_to_bin("0x64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
           "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
           "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
           "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
           "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
           "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
           "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
           "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
           "a6ad5cb4022b02709b")
     , mac   => hex_str_to_bin("0xeead9d67890cbb22392336fea1851f38") }.


blake2b_data() ->
    [#{ input => <<>>,
        output => hex_str_to_bin("0x786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
                                   "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")
      },
     #{ input => <<"abc">>,
        output => hex_str_to_bin("0xba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                                   "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
      },
     #{ input => <<"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq">>,
        output => hex_str_to_bin("0x7285ff3e8bd768d69be62b3bf18765a325917fa9744ac2f582a20850bc2b1141"
                                   "ed1b3e4528595acc90772bdf2d37dc8a47130b44f33a02e8730e5ad8e166e888")
      },
     #{ input => <<"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                   "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu">>,
        output => hex_str_to_bin("0xce741ac5930fe346811175c5227bb7bfcd47f42612fae46c0809514f9e0e3a11"
                                   "ee1773287147cdeaeedff50709aa716341fe65240f4ad6777d6bfaf9726e5e52")
      }].

blake2s_data() ->
    #{ input => <<"abc">>,
       output => hex_str_to_bin("0x508C5E8C327C14E2E1A72BA34EEB452F37458B209ED63A294D999B4C86675982")
     }.

blake2b_hmac_data() ->
    [#{ key  => hex_str_to_bin("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        data => hex_str_to_bin("0x6666666666666666666666666666666666666666666666666666666666666666"
                                 "6666666666666666666666666666666666666666666666666666666666666666"
                                 "6666666666666666666666666666666666666666666666666666666666666666"
                                 "6666666666666666666666666666666666666666666666666666666666666666"),
        hmac => hex_str_to_bin("0x4054489AA4225A07BD7F4C89330AA6412B612AADC8FA86AFBC8EC6AC2D0F3AC8"
                                 "ECDB6601B060F47488D4074C562F848B9F6168BA8CDEE22E399057B5D53129C9")
      },
     #{ key  => hex_str_to_bin("0x4054489AA4225A07BD7F4C89330AA6412B612AADC8FA86AFBC8EC6AC2D0F3AC8"
                                 "ECDB6601B060F47488D4074C562F848B9F6168BA8CDEE22E399057B5D53129C9"),
        data => hex_str_to_bin("0x01"),
        hmac => hex_str_to_bin("0x359D3AA619DF4F73E4E8EA31D05F5631C96F119D46F6BB44B5C7772B862747E7"
                                 "818D4BC8907C1EBA90B06AD7925EC5E751E4E92D0E0233F893CD3FED8DD6FB76")
      },
     #{ key  => hex_str_to_bin("0x4054489AA4225A07BD7F4C89330AA6412B612AADC8FA86AFBC8EC6AC2D0F3AC8"
                                 "ECDB6601B060F47488D4074C562F848B9F6168BA8CDEE22E399057B5D53129C9"),
        data => hex_str_to_bin("0x359D3AA619DF4F73E4E8EA31D05F5631C96F119D46F6BB44B5C7772B862747E7"
                                 "818D4BC8907C1EBA90B06AD7925EC5E751E4E92D0E0233F893CD3FED8DD6FB7602"),
        hmac => hex_str_to_bin("0x37E23F26F8445E3B5A88949B98606131774BA4D15F2C6E17A0A43972BB4EB6B5"
                                 "CBB42F57D8B1B63B4C9EA64B0493E82A6F6D3A7037C33212EF6E4F56E321D4D9")
      }].

blake2b_hkdf_data() ->
    [#{ key  => hex_str_to_bin("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        data => hex_str_to_bin("0x6666666666666666666666666666666666666666666666666666666666666666"
                                 "6666666666666666666666666666666666666666666666666666666666666666"
                                 "6666666666666666666666666666666666666666666666666666666666666666"
                                 "6666666666666666666666666666666666666666666666666666666666666666"),
        out1 => hex_str_to_bin("0x359D3AA619DF4F73E4E8EA31D05F5631C96F119D46F6BB44B5C7772B862747E7"
                                 "818D4BC8907C1EBA90B06AD7925EC5E751E4E92D0E0233F893CD3FED8DD6FB76"),
        out2 => hex_str_to_bin("0x37E23F26F8445E3B5A88949B98606131774BA4D15F2C6E17A0A43972BB4EB6B5"
                                 "CBB42F57D8B1B63B4C9EA64B0493E82A6F6D3A7037C33212EF6E4F56E321D4D9")
      }].

noise_test_vectors() ->
    parse_test_vectors("test/test_vectors.txt").

hex_str_to_bin("0x" ++ Rest) -> << <<(list_to_integer([C], 16)):4>> || C <- Rest >>.

parse_test_vectors(File) ->
    {ok, Bin} = file:read_file(File),
    #{ vectors := Vectors } = jsx:decode(Bin, [{labels, atom}, return_maps]),
    Vectors.

%% Only test supported configurations
noise_test_filter(Tests0) ->
    Tests1 = [ T || T = #{ protocol_name := Name } <- Tests0, supported(Name) ],
    Unsupported = Tests0 -- Tests1,
    case Unsupported of
        [] -> ok;
        _  ->
            ?debugFmt("NOTICE: ~p test vectors out of ~p are unsupported",
                      [length(Unsupported), length(Tests0)]),
            analyse_unsupported([Name || #{ protocol_name := Name } <- Unsupported])
    end,
    Tests1.

supported(Name) ->
    try enoise_protocol:from_name(Name), true
    catch _:_ -> false end.

analyse_unsupported(Us) ->
    UParts = lists:map(fun dismount_protocol/1, Us),
    UPats  = lists:usort([ Pat  || {Pat, _, _, _}  <- UParts, not enoise_protocol:supported_pattern(Pat) ]),
    ?debugFmt("\nUnsupported patterns: ~120p", [UPats]).

dismount_protocol(P) ->
    case string:lexemes(binary_to_list(P), "_") of
        ["Noise", PatStr, DhStr, CiphStr, HashStr] ->
            {enoise_protocol:from_name_pattern(PatStr),
             enoise_protocol:from_name_dh(DhStr),
             enoise_protocol:from_name_cipher(CiphStr),
             enoise_protocol:from_name_hash(HashStr)}
    end.
