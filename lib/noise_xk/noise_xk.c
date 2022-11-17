#include "noise_xk.h"
#include <blake2s.h>
#include <sodium.h>
#include <string.h>

const uint8_t emptyKey[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

//"Noise_XK_25519_ChaChaPoly_BLAKE2s"
const uint8_t NOISE_XK_FULL_PROTOCOL_NAME[] = {
    0x4e, 0x6f, 0x69, 0x73, 0x65, 0x5f, 0x58, 0x4b, 0x5f, 0x32, 0x35,
    0x35, 0x31, 0x39, 0x5f, 0x43, 0x68, 0x61, 0x43, 0x68, 0x61, 0x50,
    0x6f, 0x6c, 0x79, 0x5f, 0x42, 0x4c, 0x41, 0x4b, 0x45, 0x32, 0x73};

const size_t NOISE_XK_FULL_PROTOCOL_NAME_LEN = 33;
const size_t HASH_SIZE = 32;
const size_t CIPHER_KEY_SIZE = 32;

uint64_t minNonce = 0;
random_function_t *randomFunction = NULL;

void noise_xk_init(random_function_t *random_function) {
  randomFunction = random_function;
}

uint64_t incrementNounce(uint64_t n) { return n + 1; }

void noise_xk_generateKeypair(keypair_t *keypair) {
  randomFunction(keypair->private_key, 32);
  crypto_scalarmult_curve25519_base(keypair->public_key, keypair->private_key);
}

bool noise_xk_dh(const uint8_t *privateKey, const uint8_t *publicKey,
                 uint8_t *sharedSecret) {
  return crypto_scalarmult_curve25519(sharedSecret, privateKey, publicKey) == 0;
}

void noise_xk_initializeKey(cipherstate_t *cipherState, uint8_t *key) {
  cipherState->n = minNonce;
  memcpy(cipherState->k, key, CIPHER_KEY_SIZE);
}

void noise_xk_getHash(uint8_t *out, uint8_t *a, size_t aLen, uint8_t *b,
                      size_t bLen) {
  BLAKE2s_context_t blakeContext;

  BLAKE2s_reset(&blakeContext);

  if (aLen > 0) {
    BLAKE2s_update(&blakeContext, a, aLen);
  }
  if (bLen > 0) {
    BLAKE2s_update(&blakeContext, b, bLen);
  }

  BLAKE2s_finish(&blakeContext, out);
}

void noise_xk_mixHash(symmetricstate_t *symmetricState, uint8_t *data,
                      size_t dataLen) {
  noise_xk_getHash(symmetricState->h, symmetricState->h, HASH_SIZE, data,
                   dataLen);
}

void noise_xk_hashProtocolName(uint8_t *out) {
  noise_xk_getHash(out, (uint8_t *)&NOISE_XK_FULL_PROTOCOL_NAME,
                   NOISE_XK_FULL_PROTOCOL_NAME_LEN, NULL, 0);
}

void noise_xk_initializeSymmetric(symmetricstate_t *symmetricState) {
  noise_xk_hashProtocolName((uint8_t *)&symmetricState->h);
  memcpy(symmetricState->ck, symmetricState->h, HASH_SIZE);
  noise_xk_initializeKey(&symmetricState->cs, (uint8_t *)&emptyKey);
}

void noise_xk_initalizeInitiator(noisesession_t *noiseSession,
                                 uint8_t *prologue, size_t prologueSize,
                                 keypair_t *s, uint8_t *rs) {
  handshakestate_t *handshakeState = &noiseSession->hs;

  noise_xk_initializeSymmetric(&handshakeState->ss);
  noise_xk_mixHash(&handshakeState->ss, prologue, prologueSize);
  noise_xk_mixHash(&handshakeState->ss, rs, 32);
  memcpy(handshakeState->rs, rs, 32);
}

void noise_xk_initializeResponder(noisesession_t *noiseSession,
                                  uint8_t *prologue, size_t prologueSize,
                                  keypair_t *s, uint8_t *rs) {
  handshakestate_t *handshakeState = &noiseSession->hs;

  noise_xk_initializeSymmetric(&handshakeState->ss);
  noise_xk_mixHash(&handshakeState->ss, prologue, prologueSize);
  noise_xk_mixHash(&handshakeState->ss, s->public_key, 32);
  memcpy(handshakeState->rs, rs, 32);
}

void noise_xk_initSession(noisesession_t *session, bool initiator,
                          uint8_t *prologue, size_t prologueSize, keypair_t *s,
                          uint8_t *rs) {
  if (initiator) {
    noise_xk_initalizeInitiator(session, prologue, prologueSize, s, rs);
  } else {
    noise_xk_initializeResponder(session, prologue, prologueSize, s, rs);
  }

  session->i = initiator;
  session->mc = 0;
}
