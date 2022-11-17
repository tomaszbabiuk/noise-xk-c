/*
  NoiseXK - The implementation of Noise XK protocol
*/

#ifndef noise_xk_h
#define noise_xk_h

#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>

/* ---------------------------------------------------------------- *
 * TYPES                                                            *
 * ---------------------------------------------------------------- */

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
bool noise_xk_dh(const uint8_t *privateKey, const uint8_t *publicKey, uint8_t *sharedSecret);
void noise_xk_initSession(noisesession_t *session, bool initiator, uint8_t *prologue, size_t prologueSize, keypair_t *s, uint8_t *rs);

#endif