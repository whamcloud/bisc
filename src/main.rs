use biscuit::jwa::{
    ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm, SignatureAlgorithm,
};
use biscuit::jwe;
use biscuit::jwk::JWK;
use biscuit::jws::{self, Secret};
use biscuit::{ClaimsSet, Empty, RegisteredClaims, SingleOrMultiple, JWE, JWT};
use chrono::{prelude::*, Duration};
use serde::{Deserialize, Serialize};

fn authentication_request() {
    // Define our own private claims
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct AuthenticationRequest {
        username: String,
        password: String,
    }

    let now = Utc::now();

    #[allow(unused_assignments)]
    // Craft our JWS
    let expected_claims = ClaimsSet::<AuthenticationRequest> {
        registered: RegisteredClaims {
            issuer: Some("EMF".into()),
            subject: Some("node1".into()),
            audience: Some(SingleOrMultiple::Single("server".into())),
            not_before: Some(now.into()),
            issued_at: Some(now.into()),
            expiry: Some((now + Duration::hours(1)).into()),
            ..Default::default()
        },
        private: AuthenticationRequest {
            username: "admin".to_string(),
            password: "DDNSolutions4U".to_string(),
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
    let key =
        hex::decode("E4CBF7CF9206CF1E56048330A17740EA871DB523407D209F47A10F4B579532B0").unwrap();

    let key: JWK<Empty> = JWK::new_octet_key(&key, Empty {});

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
            cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
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
    println!("{}", token);

    // ... some time later, we get token back!
    let token: JWE<AuthenticationRequest, Empty, Empty> = JWE::new_encrypted(&token);

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

    let decoded_jws = decrypted_jws
        .decode(&secret, SignatureAlgorithm::RS256)
        .unwrap();

    let claims = decoded_jws.payload().unwrap();
    let user = &claims.private.username;
    let password = &claims.private.password;
    println!("username: {}, password: {}", user, password);

    // Don't forget to increment the nonce!
    nonce_counter = nonce_counter + 1u8;
}

fn session_id() {
    // Define our own private claims
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct SessionId {
        data: String,
    }

    let now = Utc::now();

    #[allow(unused_assignments)]
    // Craft our JWS
    let expected_claims = ClaimsSet::<SessionId> {
        registered: RegisteredClaims {
            issuer: Some("EMF".into()),
            subject: Some("node1".into()),
            audience: Some(SingleOrMultiple::Single("server".into())),
            not_before: Some(now.into()),
            issued_at: Some(now.into()),
            expiry: Some((now + Duration::hours(1)).into()),
            ..Default::default()
        },
        private: SessionId {
            data: "544405e6a48b452cb29d918a71596b05".into(),
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
    let key =
        hex::decode("E4CBF7CF9206CF1E56048330A17740EA871DB523407D209F47A10F4B579532B0").unwrap();

    let key: JWK<Empty> = JWK::new_octet_key(&key, Empty {});

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
            cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
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
    println!("{}", token);

    // ... some time later, we get token back!
    let token: JWE<SessionId, Empty, Empty> = JWE::new_encrypted(&token);

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

    let decoded_jws = decrypted_jws
        .decode(&secret, SignatureAlgorithm::RS256)
        .unwrap();

    let claims = decoded_jws.payload().unwrap();
    let session_id = &claims.private.data;
    println!("session_id: {}", session_id);

    // Don't forget to increment the nonce!
    nonce_counter = nonce_counter + 1u8;
}

fn bearer() {
    // Define our own private claims
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct Bearer {
        data: String,
    }

    let now = Utc::now();

    #[allow(unused_assignments)]
    // Craft our JWS
    let expected_claims = ClaimsSet::<Bearer> {
        registered: RegisteredClaims {
            issuer: Some("EMF".into()),
            subject: Some("node1".into()),
            audience: Some(SingleOrMultiple::Single("server".into())),
            not_before: Some(now.into()),
            issued_at: Some(now.into()),
            expiry: Some((now + Duration::hours(1)).into()),
            ..Default::default()
        },
        private: Bearer {
            data: "test:5976a20319f4a0977536368f61e2fc5f4126e146df".into(),
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
    let key =
        hex::decode("E4CBF7CF9206CF1E56048330A17740EA871DB523407D209F47A10F4B579532B0").unwrap();

    let key: JWK<Empty> = JWK::new_octet_key(&key, Empty {});

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
            cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
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
    println!("{}", token);

    // ... some time later, we get token back!
    let token: JWE<Bearer, Empty, Empty> = JWE::new_encrypted(&token);

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

    let decoded_jws = decrypted_jws
        .decode(&secret, SignatureAlgorithm::RS256)
        .unwrap();

    let claims = decoded_jws.payload().unwrap();
    let session_id = &claims.private.data;
    println!("session_id: {}", session_id);

    // Don't forget to increment the nonce!
    nonce_counter = nonce_counter + 1u8;
}

fn main() {
    let mut args = std::env::args();
    args.next();
    let arg = args.next().unwrap();

    match arg.as_ref() {
        "auth" => authentication_request(),
        "session" => session_id(),
        "bearer" => bearer(),
        _ => {}
    }
}
