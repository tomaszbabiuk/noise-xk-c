#include "blake2s.h"
#include "noise_xk.h"
#include "sodium.h"
#include <stdio.h>

keypair_t initiatorKeypair = {
    .public_key = {228, 234, 81,  55,  143, 120, 11,  7,   167, 6,   151,
                   247, 235, 161, 140, 0,   27,  120, 29,  17,  214, 81,
                   227, 125, 115, 164, 212, 168, 91,  250, 235, 75},
    .private_key = {234, 179, 49,  157, 96, 110, 35,  234, 64,  228, 88,
                    251, 223, 137, 210, 63, 188, 240, 142, 205, 46,  17,
                    86,  44,  174, 234, 3,  68,  128, 108, 231, 98}};

keypair_t responderKeypair = {
    .public_key = {226, 206, 58,  124, 217, 181, 220, 145, 72,  172, 105,
                   121, 111, 177, 214, 19,  247, 100, 161, 254, 32,  162,
                   246, 86,  150, 233, 38,  170, 75,  123, 30,  127},
    .private_key = {39, 37, 97,  180, 37,  108, 232, 26, 231, 20, 228,
                    84, 50, 105, 97,  121, 31,  50,  12, 79,  87, 163,
                    34, 73, 233, 80,  146, 227, 153, 36, 177, 29}};

uint8_t initiator_secret[32];
uint8_t responder_secret[32];

noisesession_t initiatorSession;

void generate_test_random_vector(void *target, size_t size) {
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

  // noise_xk_dh(initiatorKeypair.private_key,
  // responderKeypair.public_key, initiator_secret);
  // noise_xk_dh(responderKeypair.private_key,
  // initiatorKeypair.public_key, responder_secret);

  noise_xk_initSession(&initiatorSession, true, NULL, 0, &initiatorKeypair,
                       responderKeypair.public_key);

  uint8_t messageA[1] = {0x65};
  uint8_t outBuffer[100];
  size_t outBufferLen;
  noise_xk_sendMessage(&initiatorSession, messageA, sizeof(messageA),
                       &outBuffer, outBufferLen);
}