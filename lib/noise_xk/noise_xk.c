#include "noise_xk.h"
#include <blake2s.h>
#include <sodium.h>
#include <string.h>

/* ---------------------------------------------------------------- *
 * CONSTANTS                                                        *
 * ---------------------------------------------------------------- */
uint8_t emptyKey[32] = {
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
};

uint64_t minNonce = 0;
BLAKE2s_context_t blakeContext;
random_function_t* randomFunction = NULL;

void noise_xk_init(random_function_t *random_function)
{
	randomFunction = random_function;
	BLAKE2s_reset(&blakeContext);
}

uint64_t incrementNounce(uint64_t n)
{
	return n + 1;
}

void noise_xk_generateKeypair(keypair_t *keypair)
{
	randomFunction(keypair->private_key, 32);
	crypto_scalarmult_curve25519_base(keypair->public_key, keypair->private_key);
}

void noise_xk_dh(const uint8_t *privateKey, const uint8_t *publicKey, uint8_t *sharedSecret)
{
	crypto_scalarmult_curve25519(sharedSecret, privateKey, publicKey);
}

/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

void initializeKey(cipherstate_t* cipherState, uint8_t* key) {
	cipherState->n = minNonce;	
	memcpy(cipherState->k, key, CIPHER_KEY_SIZE);
}

/* GO
func initializeKey(k [32]byte) cipherstate {
 	return cipherstate{k, minNonce}
 }
*/

void getHash(uint8_t* out, uint8_t* in, size_t inLen) {

}

void hashProtocolName(uint8_t* out)
{
	getHash(out, (uint8_t*)&NOISE_XK_FULL_PROTOCOL_NAME, NOISE_XK_FULL_PROTOCOL_NAME_LEN);
}

void initializeSymmetric(symmetricstate_t *symmetricState)
{
	hashProtocolName(symmetricState->h);
	memcpy(symmetricState->ck, symmetricState->h, HASH_SIZE);
	initializeKey(&symmetricState->cs, emptyKey);
}

void initalizeInitiator(noisesession_t *noiseSession, uint8_t *prologue, size_t prologueSize, keypair_t *s, uint8_t *rs)
{
	handshakestate_t* handshakeState = &noiseSession->hs;

	initializeSymmetric(&handshakeState->ss);
	// mixHash(handshakeState->ss, prologue, prologueSize);
	// mixHash(handshakeState->ss, rs);
	handshakeState->s = *s;
	memcpy(handshakeState->rs, rs, 32);
}

void noise_xk_initSession(noisesession_t *session, bool initiator, uint8_t *prologue, size_t prologueSize, keypair_t *s, uint8_t *rs)
{
	if (initiator)
	{
		initalizeInitiator(session, prologue, prologueSize, s, rs);
	}
	else
	{
		// session->hs = initializeResponder(prologue, prologueSize, s, rs, psk);
	}

	session->i = initiator;
	session->mc = 0;
}
