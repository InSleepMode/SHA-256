# SHA-256 (Secure Hash Algorithm 256-bit)


SHA-2 (Secure Hash Algorithm Version 2) is a family of cryptographic hash functions, including SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256, and SHA-512/224.

Hash functions are designed to create “fingerprints” or “digests” for messages of arbitrary length. They are used in various applications or components related to information security.

## Algorithm
**General description**

SHA-2 hash functions are based on the Merkle–Damgård construction.

The input message, after padding, is divided into blocks, each block into 16 words. The algorithm processes each block of the message through a loop of 64 or 80 iterations (rounds). In each iteration, 2 words are transformed, and the transformation function is defined by the other words. The results of processing each block are added together, and the sum is the value of the hash function. However, the initialization of the internal state is produced by the result of processing the previous block. Therefore, blocks cannot be processed independently and then simply combined.

The algorithm uses the following bitwise operations:
- ǁ — concatenation,
- + — addition,
- and — bitwise AND,
- xor — bitwise XOR,
- shr (shift right) — logical right shift,
- rotr (rotate right) — cyclic right shift.

## Cryptanalysis
Cryptanalysis of a hash function involves studying its resistance to at least the following types of attacks:

- Finding collisions, i.e. different messages with the same hash — this determines the security of digital signatures using this hash algorithm.
- Finding a preimage, i.e. an unknown message from its hash — this determines the security of storing password hashes for authentication purposes.

In 2003, Gilbert and Handschuh analyzed SHA-2 but did not find any vulnerabilities. However, in March 2008, Indian researchers Somitra Kumar Sanadhya and Palash Sarkar published collisions for 22-round versions of SHA-256 and SHA-512. In September of the same year, they presented a method for constructing collisions for truncated versions of SHA-2 (21 rounds). Later, methods were found for constructing collisions for 31-round SHA-256 and for 27-round SHA-512.

The algorithm was also studied for resistance to preimage attacks. The latest theoretical attack is a preimage attack on the 45-round version of SHA-256 with a complexity of 2^255.5 operations. The best practical result is finding preimages for an 18-round compression function.

Due to the algorithmic similarity of SHA-2 to SHA-1 and the latter’s potential vulnerabilities, it was decided that SHA-3 would be based on a completely different algorithm. On October 2, 2012, NIST approved Keccak as the SHA-3 algorithm.

## Realisation 
*File with realisation: `SHA256.cs`

## Example
```
SHA-256("The quick brown fox jumps over the lazy dog") 
 = D7A8FBB3 07D78094 69CA9ABC B0082E4F 8D5651E4 6D3CDB76 2D02D0BF 37C9E592
```

## Literature
[SHA-256](https://en.wikipedia.org/wiki/SHA-2)
