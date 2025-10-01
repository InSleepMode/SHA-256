using System;

class SHA256
{
    private uint[] state;
    private ulong ProcessedBitsCount;
    private byte[] buffer;
    private int currentSizeOfBuffer;


    private static readonly uint[] roundConstants =
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    public SHA256() { Initialize(); } //Create an object

    private void Initialize()
    {
        //Enhance memory for the state
        state = new uint[8]; // 8 (32bit)words array
        buffer = new byte[64]; // One block size (512bit)

        //initial hash values(fractional part of sqrt from 8 first prime numbers)
        state[0] = 0x6a09e667; //sqrt2
        state[1] = 0xbb67ae85; //sqrt3
        state[2] = 0x3c6ef372; //sqrt5
        state[3] = 0xa54ff53a; //sqrt7
        state[4] = 0x510e527f; //sqrt11
        state[5] = 0x9b05688c; //sqrt13
        state[6] = 0x1f83d9ab; //sqrt17
        state[7] = 0x5be0cd19; //sqrt19

        ProcessedBitsCount = 0;
        currentSizeOfBuffer = 0;

    }


    //auxiliary functions 
    private static uint rightRotate(uint word, int bits)
    {
        return (word >> bits | word << (32 - bits));
    }

    private static uint choiceFunc(uint e, uint f, uint g)
    {
        return (e & f) ^ ((~e) & g);
        //chooses bits from f or g in dependence of e value
    }

    private static uint majorityFunc(uint a, uint b, uint c)
    {
        return (a & b) ^ (a & c) ^ (b & c);
        //returns the major value between a,b,c
    }

    private static uint Sigma0(uint a)
    {
        return rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
    }

    private static uint Sigma1(uint e)
    {
        return rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
    }

    private static uint miniSigma0(uint word)
    {
        return rightRotate(word, 7) ^ rightRotate(word, 18) ^ (word >> 3);

    }

    private static uint miniSigma1(uint word)
    {
        return rightRotate(word, 17) ^ rightRotate(word, 19) ^ (word >> 10);
    }

    private void Transform(byte[] chunk)
    {
        uint[] w = new uint[64];
        uint a, b, c, d, e, f, g, h;

        for (int i = 0; i < 16; ++i)
        {
            w[i] = (uint)chunk[i * 4] << 24 | (uint)chunk[i * 4 + 1] << 16 |
                   (uint)chunk[i * 4 + 2] << 8 | (uint)chunk[i * 4 + 3];

        }

        for (int i = 16; i < 64; ++i)
        {
            w[i] = w[i - 16] + miniSigma0(w[i - 15]) + w[i - 7] + miniSigma1(w[i - 2]);
        }

        //initialise working variables to current hash value
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];

        for (int i = 0; i < 64; ++i)
        {
            uint temp1 = h + Sigma1(e) + choiceFunc(e, f, g) + roundConstants + w[i];
            uint temp2 = Sigma0(a) + majorityFunc(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;


            //add the compressed chunk to the current hash volume 
            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }
    }


    //producing the final hash value (big-endian)
    //TODO: array enhancer
    //TODO: digestFunc
    //TODO: pre-processing (Padding)
    /*
    Pre-processing (Padding):
    begin with the original message of length L bits
    append a single '1' bit
    append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
    append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
    such that the bits in the message are: <original message of length L> 1 <K zeros> <L as 64 bit integer> , (the number of bits will be a multiple of 512)

    Process the message in successive 512-bit chunks:
    break message into 512-bit chunks
    for each chunk
        create a 64-entry message schedule array w[0..63] of 32-bit words
        (The initial values in w[0..63] don't matter, so many implementations zero them here)
        copy chunk into first 16 words w[0..15] of the message schedule array
    */

}
