#ifndef CMLKEM_NATIVE_SWIFT_H
#define CMLKEM_NATIVE_SWIFT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MLKEM_NATIVE_SWIFT_768_PUBLIC_KEY_BYTES 1184
#define MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_BYTES 1088
#define MLKEM_NATIVE_SWIFT_768_SHARED_SECRET_BYTES 32
#define MLKEM_NATIVE_SWIFT_768_SECRET_KEY_BYTES 2400
#define MLKEM_NATIVE_SWIFT_768_KEYPAIR_SEED_BYTES 64
#define MLKEM_NATIVE_SWIFT_768_ENCAPSULATION_SEED_BYTES 32

int mlkem_native_swift_768_keypair_derand(
    uint8_t pk[MLKEM_NATIVE_SWIFT_768_PUBLIC_KEY_BYTES],
    uint8_t sk[MLKEM_NATIVE_SWIFT_768_SECRET_KEY_BYTES],
    const uint8_t seed[MLKEM_NATIVE_SWIFT_768_KEYPAIR_SEED_BYTES]);

int mlkem_native_swift_768_encapsulate_derand(
    uint8_t ct[MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_BYTES],
    uint8_t ss[MLKEM_NATIVE_SWIFT_768_SHARED_SECRET_BYTES],
    const uint8_t pk[MLKEM_NATIVE_SWIFT_768_PUBLIC_KEY_BYTES],
    const uint8_t seed[MLKEM_NATIVE_SWIFT_768_ENCAPSULATION_SEED_BYTES]);

int mlkem_native_swift_768_decapsulate(
    uint8_t ss[MLKEM_NATIVE_SWIFT_768_SHARED_SECRET_BYTES],
    const uint8_t ct[MLKEM_NATIVE_SWIFT_768_CIPHERTEXT_BYTES],
    const uint8_t sk[MLKEM_NATIVE_SWIFT_768_SECRET_KEY_BYTES]);

int mlkem_native_swift_768_check_public_key(
    const uint8_t pk[MLKEM_NATIVE_SWIFT_768_PUBLIC_KEY_BYTES]);

int mlkem_native_swift_768_check_secret_key(
    const uint8_t sk[MLKEM_NATIVE_SWIFT_768_SECRET_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif
