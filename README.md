# EllipticCurveofDiffieHellman
psuedocode of elliptic curve of diffie helman for code written  in python

## ECDH (Elliptic curve of Diffie Hellman) β Key Exchange Algorithm
The system was established in 1976 by Whitfield Diffie and Martin Hellman , it is a scheme that
consist of key agreement, key agreement refers to which indicates that when two or more parties uses
a protocol that will safely exchange a consequent key value. It suggested that the Diffie-Hellman
key exchange is established on the idea of that it is quite difficult to compute a discrete logarithm
above a finite field. It utilized the modular exponentiation so it could yield exchange data encryption
key so all the sides communication will exchange it. By multiplying points, Neal Koblits and VS
Miller used this method of Elliptic curve over a finite field to yield the data that both parties would
share.
The user to keys used to access the cloud data is generated the following way, nominating a point π
on the curve and a number assume it will be π π€βπππ (1 β€ π β₯ π β 1), then we will be calculating
π which is the Public key by the equation, π which the private key.
π = π β π
The receiver decrypts the encrypted message sent by the sender using the saved public key. He uses
his own private key.

## Algorithm of the code
The algorithm of the code we are implementing is Diffie Helman key exchange, and we will state the
algorithm in this section.
The steps of the algorithm as:
1. Alice will start by producing a random pair of Keys by the formula
a. {PrivateKeyOfAlice, PublicKeyOfAlice = PrivateKeyOfAlice *G}
2. Bob will start by producing a random pair of keys by the formula
a. {PrivateKeyOfBob, PublicKeyOfBob = PrivateKeyOfBob *G}
3. Then both Alice along Bob will exchange each otherβs public key through an insecure channel.
4. Then Alice and Bob will calculate the shared key between them by the formulas
a. Alice, Shared Key = PublicKeyOfBob * PrivateKeyOfAlice
b. Bob, Shared Key = PublicKeyOfAlice * PrivateKeyOfBob
5. For now, both Alice and Bob will possess the shared key were this formula proves it
a. Shared Key == PublicKeyOfBob * PrivateKeyOfAlice == PublicKeyOfAlice *
PrivateKeyOfBob

## Pseudocode of ECDH 

A point in the group and the order of the group (in this case the number of points on the elliptic curve)
are public knowledge.
Bob chooses a secret message (a number b with 0 < b < n).
Alice chooses a secret message (a number a with 0 < a < n).
