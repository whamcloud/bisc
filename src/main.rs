use biscuit::{
    jwa::{self, Algorithm},
    jwk::{AlgorithmParameters, CommonParameters, RSAKeyParameters},
};
use num::BigUint;

fn main() {
    use biscuit::jwa::{
        ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm, SignatureAlgorithm,
    };
    use biscuit::jwe;
    use biscuit::jwk::JWK;
    use biscuit::jws::{self, Secret};
    use biscuit::{ClaimsSet, Empty, RegisteredClaims, SingleOrMultiple, JWE, JWT};
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;

    // Define our own private claims
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct PrivateClaims {
        company: String,
        department: String,
    }

    #[allow(unused_assignments)]
    // Craft our JWS
    let expected_claims = ClaimsSet::<PrivateClaims> {
        registered: RegisteredClaims {
            issuer: Some(FromStr::from_str("https://www.acme.com").unwrap()),
            subject: Some(FromStr::from_str("John Doe").unwrap()),
            audience: Some(SingleOrMultiple::Single(
                FromStr::from_str("htts://acme-customer.com").unwrap(),
            )),
            not_before: Some(1234.into()),
            ..Default::default()
        },
        private: PrivateClaims {
            department: "Toilet Cleaning".to_string(),
            company: "ACME".to_string(),
        },
    };

    let expected_jwt = JWT::new_decoded(
        From::from(jws::RegisteredHeader {
            algorithm: SignatureAlgorithm::RS256,
            ..Default::default()
        }),
        expected_claims.clone(),
    );

    let secret = Secret::rsa_keypair_from_file("private_key.der").unwrap();

    let jws = expected_jwt.into_encoded(&secret).unwrap();

    // Encrypt the token

    // You would usually have your own AES key for this, but we will use a zeroed key as an example
    //     RSA Private-Key: (2048 bit, 2 primes)
    // modulus:
    let n_str = "
        00:db:e3:76:38:bb:0c:5f:9b:e7:4c:1b:16:0e:20:
        1d:69:99:e4:2e:56:e5:ff:7d:b1:c4:b3:ce:75:8b:
        1c:21:9e:87:fa:b8:ff:80:5c:26:00:7c:0b:54:06:
        27:30:26:24:5b:e4:bb:7b:d8:fc:ca:f2:53:79:7e:
        55:0a:cd:d7:8b:17:ac:11:c3:36:20:f4:d3:ef:23:
        b0:9d:79:54:01:80:07:a6:25:d9:36:d0:e9:24:87:
        65:2d:83:3e:52:3d:da:03:b4:32:ca:c8:11:f7:ca:
        91:4c:2b:4c:3d:0e:56:87:76:0b:12:cb:6e:72:eb:
        3b:57:e8:d4:b1:9f:33:ad:c4:78:89:a5:b2:2e:b2:
        b5:b3:ee:f0:14:2a:98:ed:2e:fb:f5:07:d5:37:bc:
        b3:44:76:a7:50:e1:84:81:ab:2e:f7:35:bb:f8:53:
        7d:40:c6:62:e6:be:a2:e1:bf:c4:e6:6e:ab:71:e6:
        73:80:3a:d4:62:9d:0e:e7:d7:8c:88:91:25:b2:ca:
        12:13:1c:e1:a8:11:1f:97:46:08:a8:99:ff:88:90:
        3a:14:78:5b:bc:8e:f2:1d:b0:c5:86:f9:16:bf:d3:
        da:fd:1a:ae:d6:eb:97:7a:65:02:d0:01:7d:36:74:
        cf:55:a5:0d:7a:e0:fd:66:b3:42:ff:fe:8c:98:ee:
        8b:05";
    // publicExponent: 65537 (0x10001)
    let e = 65537;
    // privateExponent:
    let d_str = "
        29:4e:3e:4c:03:df:1c:2a:b6:35:56:b5:3a:ec:0f:
        7a:61:dd:3a:53:3a:9b:56:ea:48:f0:19:ed:7c:b7:
        49:1d:75:9f:c4:96:c2:6f:0c:f8:74:54:d0:70:e3:
        75:a9:04:95:7a:8f:39:81:96:63:2d:48:3e:ff:5b:
        4c:4f:44:99:2d:56:36:73:fc:3c:0e:a1:ad:3f:80:
        12:e4:d2:c2:01:61:ee:75:17:ab:b3:6c:c8:5e:e2:
        c3:bc:ee:bd:16:3f:59:08:c5:ad:d0:0d:88:05:b6:
        6b:9f:8a:8f:c1:9c:c1:8f:8c:1e:f8:b6:03:c2:6a:
        80:66:0d:66:5c:68:a1:d0:78:21:5a:31:b5:e3:05:
        3f:8c:63:16:28:1d:27:83:5c:81:ee:fa:c3:51:31:
        48:0e:69:fb:a1:0f:34:5c:ef:e2:7c:76:8e:32:c0:
        5d:06:48:7c:0b:f6:1e:3d:02:dd:ef:34:05:0a:9f:
        4a:8d:b3:d8:1a:ee:3a:d9:18:cd:85:a5:d4:3e:bb:
        ee:c5:56:35:42:b9:37:e7:2b:e7:07:d2:e3:6e:f8:
        e2:48:6e:1c:7e:5b:f4:6b:bc:36:ff:fd:47:58:94:
        4c:2a:f6:f2:fb:49:31:91:10:90:24:b8:89:81:d2:
        16:0f:5a:7a:43:2e:cb:88:d3:42:7c:cf:94:99:fb:
        e1";

    fn decode_byte_string(input: &str) -> Vec<u32> {
        let oneline: String = input.chars().filter(|c| *c != '\n' && *c != ' ').collect();
        let bytes = oneline.split(':');
        let mut count = 0;
        let mut word: u32 = 0;
        let mut result = vec![];
        for b in bytes {
            let b = u8::from_str_radix(b, 16).unwrap();
            word += u32::from(b) * 256u32.pow(count);
            count += 1;
            if count > 3 {
                result.push(word);
                count = 0;
                word = 0;
            }
        }
        result
    }

    let n = BigUint::new(decode_byte_string(n_str));
    let d = Some(BigUint::new(decode_byte_string(d_str)));

    let key: JWK<Empty> = JWK {
        common: CommonParameters {
            algorithm: Some(Algorithm::Signature(jwa::SignatureAlgorithm::RS256)),
            key_id: Some("2011-04-29".to_string()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: Default::default(),
            n,
            e: BigUint::new(vec![e]),
            d,
            ..Default::default()
        }),
        additional: Default::default(),
    };

    // We need to create an `EncryptionOptions` with a nonce for AES GCM encryption.
    // You must take care NOT to reuse the nonce. You can simply treat the nonce as a 96 bit
    // counter that is incremented after every use
    let mut nonce_counter = num::BigUint::from_bytes_le(&vec![0; 96 / 8]);
    // Make sure it's no more than 96 bits!
    assert!(nonce_counter.bits() <= 96);
    let mut nonce_bytes = nonce_counter.to_bytes_le();
    // We need to ensure it is exactly 96 bits
    nonce_bytes.resize(96 / 8, 0);
    let options = EncryptionOptions::AES_GCM { nonce: nonce_bytes };

    // Construct the JWE
    let jwe = JWE::new_decrypted(
        From::from(jwe::RegisteredHeader {
            cek_algorithm: KeyManagementAlgorithm::RSA1_5,
            enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
            media_type: Some("JOSE".to_string()),
            content_type: Some("JOSE".to_string()),
            ..Default::default()
        }),
        jws.clone(),
    );

    // Encrypt
    let encrypted_jwe = jwe.encrypt(&key, &options).unwrap();

    let token = encrypted_jwe.unwrap_encrypted().to_string();

    // Now, send `token` to your clients

    // ... some time later, we get token back!
    let token: JWE<PrivateClaims, Empty, Empty> = JWE::new_encrypted(&token);

    // Decrypt
    let decrypted_jwe = token
        .into_decrypted(
            &key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A256GCM,
        )
        .unwrap();

    let decrypted_jws = decrypted_jwe.payload().unwrap();
    assert_eq!(jws, *decrypted_jws);

    // Don't forget to increment the nonce!
    nonce_counter = nonce_counter + 1u8;
}
