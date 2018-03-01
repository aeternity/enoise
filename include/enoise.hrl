-define(MAX_NONCE, 16#FFFFFFFFFFFFFFFF).
-define(AD_LEN, 16).

-record(noise_protocol,
        { hs_pattern = noiseNN      %:: noise_hs_pattern()
        , dh         = dh25519      %:: noise_dh()
        , cipher     = 'ChaChaPoly' %:: noise_cipher()
        , hash       = blake2b      %:: noise_hash()
        }).

-record(key_pair, { puk, pik }).

-record(noise_ss, { cs        :: enoise_cipher_state:state()
                  , ck = <<>> :: binary()
                  , h  = <<>> :: binary()
                  , hash = blake2b }).

-record(noise_hs, { ss :: #noise_ss{} | undefined
                  , s  :: #key_pair{} | undefined
                  , e  :: #key_pair{} | undefined
                  , rs :: binary() | undefined
                  , re :: binary() | undefined
                  , role = initiatior :: initiator | responder
                  , dh
                  , msgs = [] }).
