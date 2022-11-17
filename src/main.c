#include "blake2s.h"
#include "noise_xk.h"
#include "sodium.h"
#include <stdio.h>

keypair_t initiatorKeypair;
keypair_t responderKeypair;
uint8_t initiator_secret[32];
uint8_t responder_secret[32];

noisesession_t initiatorSession;

void generate_test_random_vector(void *target, size_t size) {
  // TODO:

  uint8_t *targetAsUint8 = (uint8_t *)target;
  for (size_t i = 0; i < size; i++) {
    targetAsUint8[i] = i % 255;
  }
}

int main() {
  printf("Hello Noise XK");

  noise_xk_init(generate_test_random_vector);

  printf("Generating keypairs");
  noise_xk_generateKeypair(&initiatorKeypair);
  noise_xk_generateKeypair(&responderKeypair);

  // noise_xk_dh(initiatorKeypair.private_key, responderKeypair.public_key,
  // initiator_secret); noise_xk_dh(responderKeypair.private_key,
  // initiatorKeypair.public_key, responder_secret);

  noise_xk_initSession(&initiatorSession, true, NULL, 0, &initiatorKeypair,
                       responderKeypair.public_key);
}