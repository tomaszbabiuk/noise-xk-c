/*
  NoiseXK.cpp - The implementation of Noise XK protocol
*/

#ifndef NoiseXK_h
#define NoiseXK_h

#include <ArduinoTypes.h>

#ifdef __cplusplus
extern "C" {
#endif


/* ---------------------------------------------------------------- *
 * TYPES                                                            *
 * ---------------------------------------------------------------- */

//"Noise_XK_25519_ChaChaPoly_BLAKE2s"
const uint8_t NOISE_XK_FULL_PROTOCOL_NAME[] = {
    0x4e, 0x6f, 0x69, 0x73, 0x65, 0x5f, 0x58, 0x4b, 0x5f, 0x32,
    0x35, 0x35, 0x31, 0x39, 0x5f, 0x43, 0x68, 0x61, 0x43, 0x68,
    0x61, 0x50, 0x6f, 0x6c, 0x79, 0x5f, 0x42, 0x4c, 0x41, 0x4b,
    0x45, 0x32, 0x73}; 

const size_t NOISE_XK_FULL_PROTOCOL_NAME_LEN = 33;
const size_t HASH_SIZE = 32;
const size_t CIPHER_KEY_SIZE = 32;

typedef struct
{
  uint8_t public_key[32];
  uint8_t private_key[32];
} keypair_t;

typedef struct
{
  uint8_t ne[32];
  uint8_t ns[1024]; // todo check this size
  uint8_t ciphertext[1024];
} messagebuffer_t;

typedef struct
{
  uint8_t k[32];
  uint64_t n;
} cipherstate_t;

typedef struct
{
  cipherstate_t cs;
  uint8_t ck[32];
  uint8_t h[32];
} symmetricstate_t;

typedef struct
{
  symmetricstate_t ss;
  keypair_t s;
  keypair_t e;
  uint8_t rs[32];
  uint8_t re[32];
} handshakestate_t;

typedef struct
{
  handshakestate_t hs;
  uint8_t h[32];
  cipherstate_t cs1;
  cipherstate_t cs2;
  uint64_t mc;
  bool i;
} noisesession_t;

/* ---------------------------------------------------------------- *
 * UTILITY FUNCTIONS                                                *
 * ---------------------------------------------------------------- */

typedef void random_function_t(void *, size_t);

void noise_xk_init(random_function_t *random_function);
uint64_t noise_xk_incrementNounce(uint64_t n);
void noise_xk_generateKeypair(keypair_t *keypair);
void noise_xk_dh(const uint8_t *privateKey, const uint8_t *publicKey, uint8_t *sharedSecret);
void noise_xk_initSession(noisesession_t *session, bool initiator, uint8_t *prologue, size_t prologueSize, keypair_t *s, uint8_t *rs);

#ifdef __cplusplus
}
#endif

#endif