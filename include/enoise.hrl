-define(MAX_NONCE, 16#FFFFFFFFFFFFFFFF).
-define(AD_LEN, 16).

-record(noise_protocol,
        { hs_pattern = noiseNN      %:: noise_hs_pattern()
        , dh         = dh25519      %:: noise_dh()
        , cipher     = 'ChaChaPoly' %:: noise_cipher()
        , hash       = blake2b      %:: noise_hash()
        }).

-record(key_pair, { puk, pik }).

-record(noise_hs, { ss :: enoise_sym_state: state()
                  , s  :: #key_pair{} | undefined
                  , e  :: #key_pair{} | undefined
                  , rs :: binary() | undefined
                  , re :: binary() | undefined
                  , role = initiatior :: initiator | responder
                  , dh
                  , msgs = [] }).
