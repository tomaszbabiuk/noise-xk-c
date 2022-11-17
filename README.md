# Noise XK
Noise XK is one of Noise protocol variations, when The responder is initialized with a pre-shared long-term static key, which is assumed to be pre-authenticated out of band by the initiator. See (https://noiseexplorer.com/patterns/XK).
This implementation is written entirely in C.

# Target
It was tested on Mac OS X (with Apple M1 chip). But the goal is to use it on embedded targets with Arduino framework.

# Shared libraries
```bash
    brew install libsodium
    brew link libsodium
```