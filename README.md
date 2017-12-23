## Crypto Guide

This project is meant to be a readable implementation of some of the most important cryptographic
algorithms.
This project is not meant to be used as a reliable source of encryption, but rather as a guide
on how certain cryptographic algorithm works.

Some of the implemented algorithms are:
    * [AES](https://en.wikipedia.org/wiki/SHA-3)
    * [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
    * [PGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy)
    * [SHA-1](https://en.wikipedia.org/wiki/SHA-1)
    * [SHA-3](https://en.wikipedia.org/wiki/SHA-3)

All code is written in python 3.5. It's only dependency is numpy, to install do:
> pip3 install numpy

To run do:
> python3 main.py -a <algorithm> --msg="Message to encrypt"


#### AES (Advanced Encryption Standard)

AES is a subset of the Rijndael cipher. It's a symmetric key cipher based on a
substitution-permutation network design. It has a block size of 128 bits and a
key size of 128, 192 and 256 bits (Only 128-bit keys are implemented in this example).
Operations are performed in a finite field known as Galois' Field. In it, addition and
substraction are xor and multiplication is a "specific" polynomial multiplication.


#### RSA (Rivest-Shamir-Adleman)

RSA is an asymmetric cryptographic protocol that is based on the difficulty of
factorizing the product of two large primes.
The user creates two keys, one of them encrypts while the other one decrypts.
By publicly sharing one of them (public key), a sender (Alice) can encrypt a
message with it, making it only readable to the holder of the private key (Bob).


#### Hybrid

A hybrid system is the combination of an asymmetric cipher, which is able to distribute
send messages privately (slow), and a symmetric cipher, which is able to encrypt messages
securely very fast. The most well-known implementation of protocol is PGP. But, to get a
generic understanding, the implemented version would be more than enough.


### SHA-1 (Secure Hash Algorithm)

SHA-1 is a cryptographic hash function which takes an input and products a 20-byte hash value.
SHA-1 is currently not secure, but it's the base of most hashing algorithms.
