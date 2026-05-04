#include "CMLKEMNativeSwift.h"

#include <string.h>

#include "../../Vendor/mlkem-native/mlkem/mlkem_native.c"

#define MLKEM_NATIVE_SWIFT_SYMBYTES 32
#define MLKEM_NATIVE_SWIFT_ERR_FAIL -1

int mlkem_native_swift_768_keypair_derand(
    uint8_t pk[MLKEM_NATIVE_SWIFT_768_PUBLIC_KEY_BYTES],
    uint8_t sk[MLKEM_NATIVE_SWIFT_768_SECRET_KEY_BYTES],
    const uint8_t seed[MLKEM_NATIVE_SWIFT_768_KEYPAIR_SEED_BYTES])
{
    return PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand(pk, sk, seed);
}

int mlkem_native_swift_768_encapsulate_derand(
    uint8_t ct[MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_BYTES],
    uint8_t ss[MLKEM_NATIVE_SWIFT_768_SHARED_SECRET_BYTES],
    const uint8_t pk[MLKEM_NATIVE_SWIFT_768_PUBLIC_KEY_BYTES],
    const uint8_t seed[MLKEM_NATIVE_SWIFT_768_ENCAPSULATION_SEED_BYTES])
{
    return PQCP_MLKEM_NATIVE_MLKEM768_enc_derand(ct, ss, pk, seed);
}

int mlkem_native_swift_768_decapsulate(
    uint8_t ss[MLKEM_NATIVE_SWIFT_768_SHARED_SECRET_BYTES],
    const uint8_t ct[MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_BYTES],
    const uint8_t sk[MLKEM_NATIVE_SWIFT_768_SECRET_KEY_BYTES])
{
    return PQCP_MLKEM_NATIVE_MLKEM768_dec(ss, ct, sk);
}

int mlkem_native_swift_768_check_public_key(
    const uint8_t pk[MLKEM_NATIVE_SWIFT_768_PUBLIC_KEY_BYTES])
{
    return PQCP_MLKEM_NATIVE_MLKEM768_check_pk(pk);
}

int mlkem_native_swift_768_check_secret_key(
    const uint8_t sk[MLKEM_NATIVE_SWIFT_768_SECRET_KEY_BYTES])
{
    return PQCP_MLKEM_NATIVE_MLKEM768_check_sk(sk);
}

int mlkem_native_swift_768_public_key_to_incremental(
    uint8_t header[MLKEM_NATIVE_SWIFT_768_INCREMENTAL_HEADER_BYTES],
    uint8_t ek_vector[MLKEM_NATIVE_SWIFT_768_ENCAPSULATION_KEY_VECTOR_BYTES],
    const uint8_t pk[MLKEM_NATIVE_SWIFT_768_PUBLIC_KEY_BYTES])
{
    int ret = PQCP_MLKEM_NATIVE_MLKEM768_check_pk(pk);
    if (ret != 0) {
        return ret;
    }
    memcpy(ek_vector, pk, MLKEM_NATIVE_SWIFT_768_ENCAPSULATION_KEY_VECTOR_BYTES);
    memcpy(header, pk + MLKEM_NATIVE_SWIFT_768_ENCAPSULATION_KEY_VECTOR_BYTES, MLKEM_NATIVE_SWIFT_SYMBYTES);
    PQCP_MLKEM_NATIVE_MLKEM768_sha3_256(header + MLKEM_NATIVE_SWIFT_SYMBYTES, pk, MLKEM_NATIVE_SWIFT_768_PUBLIC_KEY_BYTES);
    return 0;
}

int mlkem_native_swift_768_public_key_from_incremental(
    uint8_t pk[MLKEM_NATIVE_SWIFT_768_PUBLIC_KEY_BYTES],
    const uint8_t header[MLKEM_NATIVE_SWIFT_768_INCREMENTAL_HEADER_BYTES],
    const uint8_t ek_vector[MLKEM_NATIVE_SWIFT_768_ENCAPSULATION_KEY_VECTOR_BYTES])
{
    uint8_t expected_hash[MLKEM_NATIVE_SWIFT_SYMBYTES];
    memcpy(pk, ek_vector, MLKEM_NATIVE_SWIFT_768_ENCAPSULATION_KEY_VECTOR_BYTES);
    memcpy(pk + MLKEM_NATIVE_SWIFT_768_ENCAPSULATION_KEY_VECTOR_BYTES, header, MLKEM_NATIVE_SWIFT_SYMBYTES);
    PQCP_MLKEM_NATIVE_MLKEM768_sha3_256(expected_hash, pk, MLKEM_NATIVE_SWIFT_768_PUBLIC_KEY_BYTES);
    if (mlk_ct_memcmp(expected_hash, header + MLKEM_NATIVE_SWIFT_SYMBYTES, MLKEM_NATIVE_SWIFT_SYMBYTES) != 0) {
        mlk_zeroize(expected_hash, sizeof(expected_hash));
        return MLKEM_NATIVE_SWIFT_ERR_FAIL;
    }
    mlk_zeroize(expected_hash, sizeof(expected_hash));
    return PQCP_MLKEM_NATIVE_MLKEM768_check_pk(pk);
}

int mlkem_native_swift_768_encapsulate_part1_derand(
    uint8_t encaps_secret[MLKEM_NATIVE_SWIFT_768_INCREMENTAL_ENCAPSULATION_SECRET_BYTES],
    uint8_t ct1[MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_PART1_BYTES],
    uint8_t ss[MLKEM_NATIVE_SWIFT_768_SHARED_SECRET_BYTES],
    const uint8_t header[MLKEM_NATIVE_SWIFT_768_INCREMENTAL_HEADER_BYTES],
    const uint8_t seed[MLKEM_NATIVE_SWIFT_768_ENCAPSULATION_SEED_BYTES])
{
    uint8_t dummy_pk[MLKEM_NATIVE_SWIFT_768_PUBLIC_KEY_BYTES] = {0};
    uint8_t ct[MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_BYTES];
    uint8_t kr[2 * MLKEM_NATIVE_SWIFT_SYMBYTES];
    int ret;

    memcpy(encaps_secret, seed, MLKEM_NATIVE_SWIFT_SYMBYTES);
    memcpy(encaps_secret + MLKEM_NATIVE_SWIFT_SYMBYTES, header + MLKEM_NATIVE_SWIFT_SYMBYTES, MLKEM_NATIVE_SWIFT_SYMBYTES);
    PQCP_MLKEM_NATIVE_MLKEM768_sha3_512(kr, encaps_secret, 2 * MLKEM_NATIVE_SWIFT_SYMBYTES);
    memcpy(ss, kr, MLKEM_NATIVE_SWIFT_SYMBYTES);
    memcpy(encaps_secret + MLKEM_NATIVE_SWIFT_SYMBYTES, kr + MLKEM_NATIVE_SWIFT_SYMBYTES, MLKEM_NATIVE_SWIFT_SYMBYTES);

    memcpy(dummy_pk + MLKEM_NATIVE_SWIFT_768_ENCAPSULATION_KEY_VECTOR_BYTES, header, MLKEM_NATIVE_SWIFT_SYMBYTES);
    ret = PQCP_MLKEM_NATIVE_MLKEM768_indcpa_enc(ct, encaps_secret, dummy_pk, encaps_secret + MLKEM_NATIVE_SWIFT_SYMBYTES);
    if (ret != 0) {
        goto cleanup;
    }
    memcpy(ct1, ct, MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_PART1_BYTES);

cleanup:
    mlk_zeroize(kr, sizeof(kr));
    mlk_zeroize(ct, sizeof(ct));
    mlk_zeroize(dummy_pk, sizeof(dummy_pk));
    if (ret != 0) {
        mlk_zeroize(encaps_secret, MLKEM_NATIVE_SWIFT_768_INCREMENTAL_ENCAPSULATION_SECRET_BYTES);
        mlk_zeroize(ct1, MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_PART1_BYTES);
        mlk_zeroize(ss, MLKEM_NATIVE_SWIFT_768_SHARED_SECRET_BYTES);
    }
    return ret;
}

int mlkem_native_swift_768_encapsulate_part2(
    uint8_t ct2[MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_PART2_BYTES],
    const uint8_t encaps_secret[MLKEM_NATIVE_SWIFT_768_INCREMENTAL_ENCAPSULATION_SECRET_BYTES],
    const uint8_t header[MLKEM_NATIVE_SWIFT_768_INCREMENTAL_HEADER_BYTES],
    const uint8_t ek_vector[MLKEM_NATIVE_SWIFT_768_ENCAPSULATION_KEY_VECTOR_BYTES])
{
    uint8_t pk[MLKEM_NATIVE_SWIFT_768_PUBLIC_KEY_BYTES];
    uint8_t ct[MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_BYTES];
    int ret = mlkem_native_swift_768_public_key_from_incremental(pk, header, ek_vector);
    if (ret != 0) {
        return ret;
    }
    ret = PQCP_MLKEM_NATIVE_MLKEM768_indcpa_enc(ct, encaps_secret, pk, encaps_secret + MLKEM_NATIVE_SWIFT_SYMBYTES);
    if (ret != 0) {
        goto cleanup;
    }
    memcpy(ct2, ct + MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_PART1_BYTES, MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_PART2_BYTES);

cleanup:
    mlk_zeroize(ct, sizeof(ct));
    mlk_zeroize(pk, sizeof(pk));
    if (ret != 0) {
        mlk_zeroize(ct2, MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_PART2_BYTES);
    }
    return ret;
}

int mlkem_native_swift_768_decapsulate_parts(
    uint8_t ss[MLKEM_NATIVE_SWIFT_768_SHARED_SECRET_BYTES],
    const uint8_t ct1[MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_PART1_BYTES],
    const uint8_t ct2[MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_PART2_BYTES],
    const uint8_t sk[MLKEM_NATIVE_SWIFT_768_SECRET_KEY_BYTES])
{
    uint8_t ct[MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_BYTES];
    int ret;
    memcpy(ct, ct1, MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_PART1_BYTES);
    memcpy(ct + MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_PART1_BYTES, ct2, MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_PART2_BYTES);
    ret = PQCP_MLKEM_NATIVE_MLKEM768_dec(ss, ct, sk);
    mlk_zeroize(ct, sizeof(ct));
    return ret;
}
