#include "../../Vendor/mlkem-native/mlkem/mlkem_native.c"

#include "CMLKEMNativeSwift.h"

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
