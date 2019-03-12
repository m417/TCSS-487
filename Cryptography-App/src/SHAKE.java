import java.util.Arrays;

/**
 * Experimental cSHAKE256 and KMACXOF256 implementation.
 *
 * @author Markku-Juhani Saarinen (original Keccak and Model.SHAKE implementation in C)
 * @author Paulo S. L. M. Barreto (Java version, cSHAKE, KMACXOF)
 */
public class SHAKE {
    private byte[] b = new byte[200];	// 8-bit bytes
    private int pt, rsiz, mdlen;		// these don't overflow
    private static final int KECCAKF_ROUNDS = 24;

    private boolean ext = false, kmac = false;
    private static final byte[] KMAC_N = {(byte)0x4B, (byte)0x4D, (byte)0x41, (byte)0x43}; // "KMAC" in ASCII
    private static final byte[] right_encode_0 = {(byte)0x00, (byte)0x01}; // right_encode(0)

    private static final long[/*24*/] keccakf_rndc = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    private static final int[/*24*/] keccakf_rotc = {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    private static final int[/*24*/] keccakf_piln = {
            10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    /**
     * Rotate the 64-bit long value x by y positions to the left
     * @param   x any 64-bit long value
     * @param   y the left-rotation displacement
     * @return  the 64-bot long value x left-rotated by y positions
     */
    private static long ROTL64(long x, int y) {
        return (x << y) | (x >>> (64 - y));
    }

    /**
     * Apply the Keccak-f permutation to the byte-oriented state buffer v.
     * @param v
     */
    private static void sha3_keccakf(byte[/*200*/] v) {
        long[] q = new long[25]; // 64-bit words
        long[] bc = new long[5];

        // map from bytes (in v[]) to longs (in q[]).
        for (int i = 0, j = 0; i < 25; i++, j += 8) {
            q[i] =  (((long)v[j + 0] & 0xFFL)      ) | (((long)v[j + 1] & 0xFFL) <<  8) |
                    (((long)v[j + 2] & 0xFFL) << 16) | (((long)v[j + 3] & 0xFFL) << 24) |
                    (((long)v[j + 4] & 0xFFL) << 32) | (((long)v[j + 5] & 0xFFL) << 40) |
                    (((long)v[j + 6] & 0xFFL) << 48) | (((long)v[j + 7] & 0xFFL) << 56);
        }

        // actual iteration
        for (int r = 0; r < KECCAKF_ROUNDS; r++) {

            // Theta
            for (int i = 0; i < 5; i++) {
                bc[i] = q[i] ^ q[i + 5] ^ q[i + 10] ^ q[i + 15] ^ q[i + 20];
            }
            for (int i = 0; i < 5; i++) {
                long t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5) {
                    q[j + i] ^= t;
                }
            }

            // Rho Pi
            long t = q[1];
            for (int i = 0; i < 24; i++) {
                int j = keccakf_piln[i];
                bc[0] = q[j];
                q[j] = ROTL64(t, keccakf_rotc[i]);
                t = bc[0];
            }

            //  Chi
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++) {
                    bc[i] = q[j + i];
                }
                for (int i = 0; i < 5; i++) {
                    q[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }

            //  Iota
            q[0] ^= keccakf_rndc[r];
        }

        // map from longs (in q[]) to bytes (in v[]).
        for (int i = 0, j = 0; i < 25; i++, j += 8) {
            long t = q[i];
            v[j + 0] = (byte)((t      ) & 0xFF);
            v[j + 1] = (byte)((t >>  8) & 0xFF);
            v[j + 2] = (byte)((t >> 16) & 0xFF);
            v[j + 3] = (byte)((t >> 24) & 0xFF);
            v[j + 4] = (byte)((t >> 32) & 0xFF);
            v[j + 5] = (byte)((t >> 40) & 0xFF);
            v[j + 6] = (byte)((t >> 48) & 0xFF);
            v[j + 7] = (byte)((t >> 56) & 0xFF);
        }
    }

    public SHAKE() {}

    private static final byte[] left_encode_0 = {(byte)0x01, (byte)0x00}; // left_encode(0)

    /**
     * Concatenate two byte arrays.
     *
     * @param a concatenation prefix
     * @param b concatenation suffix
     * @return  a || b
     */
    private static byte[] concat(byte[] a, byte[] b) {
        int alen = (a != null) ? a.length : 0;
        int blen = (b != null) ? b.length : 0;
        byte[] c = new byte[alen + blen];
        System.arraycopy(a, 0, c, 0, alen);
        System.arraycopy(b, 0, c, alen, blen);
        return c;
    }

    /**
     * Apply the NIST encode_string primitive to S.
     *
     * @param S string to encode (if null, the encoding of "" is used)
     * @return  the encoding of S
     */
    private static byte[] encode_string(byte[] S) {
        // Validity Conditions: 0 ≤ len(S) < 2^2040
        int slen = (S != null) ? S.length : 0;
        byte[] lenS = (S != null) ? left_encode(slen << 3) : left_encode_0; // NB: bitlength, not bytelength
        byte[] encS = new byte[lenS.length + slen];
        System.arraycopy(lenS, 0, encS, 0, lenS.length);
        System.arraycopy((S != null) ? S : encS, 0, encS, lenS.length, slen);
        return encS; // left_encode(len(S)) || S.
    }

    /**
     * Apply the NIST left_encode primitive to x (which is typically the bitlength of some string).
     * @param x the integer to be left encoded
     * @return  the left encoding of x
     */
    private static byte[] left_encode(int x) {
        // Validity Conditions: 0 ≤ x < 2^2040
        // 1. Let n be the smallest positive integer for which 2^(8*n) > x.
        int n = 1;
        while ((1 << (8*n)) <= x) {
            n++;
        }
        if (n >= 256) {
            throw new RuntimeException("Left encoding overflow for length " + n);
        }
        // 2. Let x1, x2, ..., xn be the base-256 encoding of x satisfying:
        //    x = Σ 2^(8*(n-i))*x_i, for i = 1 to n.
        // 3. Let Oi = enc8(xi), for i = 1 to n.
        byte[] val = new byte[n + 1];
        for (int i = n; i > 0; i--) {
            val[i] = (byte)(x & 0xFF);
            x >>>= 8;
        }
        // 4. Let O0 = enc8(n).
        val[0] = (byte)n;
        // 5. Return O = O0 || O1 || …|| On−1 || On.
        return val;
    }

    /**
     * Apply the NIST bytepad primitive to a byte array X with encoding factor w.
     * @param X the byte array to bytepad
     * @param w the encoding factor (the output length must be a multiple of w)
     * @return the byte-padded byte array X with encoding factor w.
     */
    private static byte[] bytepad(byte[] X, int w) {
        // Validity Conditions: w > 0
        // 1. z = left_encode(w) || X.
        byte[] wenc = left_encode(w);
        byte[] z = new byte[w*((wenc.length + X.length + w - 1)/w)]; // z.length is the smallest multiple of w that fits wenc.length + X.length
        System.arraycopy(wenc, 0, z, 0, wenc.length);
        System.arraycopy(X, 0, z, wenc.length, X.length);
        // 2. len(z) mod 8 = 0 (byte-oriented implementation)
        // 3. while (len(z)/8) mod w ≠ 0: z = z || 00000000
        for (int i = wenc.length + X.length; i < z.length; i++) {
            z[i] = (byte)0;
        }
        return z;
    }

    /**
     * Initialize the SHAKE256 sponge.
     */
    public void init256() {
        Arrays.fill(this.b, (byte)0);
        this.mdlen = 32; // fixed for SHAKE256 (for SHA128 it would be 16)
        this.rsiz = 200 - 2*mdlen;
        this.pt = 0;

        this.ext = false;
        this.kmac = false;
    }

    /**
     * Initialize the cSHAKE256 sponge.
     *
     * @param N     function name
     * @param S     customization string
     */
    public void cinit256(byte[] N, byte[] S) {
        // Validity Conditions: len(N) < 2^2040 and len(S) < 2^2040
        init256();
        if ((N != null && N.length != 0) || (S != null && S.length != 0)) {
            this.ext = true; // cSHAKE instead of Model.SHAKE
            byte[] prefix = bytepad(concat(encode_string(N), encode_string(S)), 136);
            update(prefix, prefix.length);
        }
    }

    /**
     * Initialize the KMACXOF256 sponge.
     *
     * @param K     MAC key
     * @param S     customization string
     * @return
     */
    public void kinit256(byte[] K, byte[] S) {
        // Validity Conditions: len(K) < 2^2040 and len(S) < 2^2040
        byte[] encK = bytepad(encode_string(K), 136);
        cinit256(KMAC_N, S);
        this.kmac = true;
        update(encK, encK.length);
    }

    /**
     * Update the SHAKE256 sponge with a byte-oriented data chunk.
     * @param data  byte-oriented data buffer
     * @param len   byte count on the buffer (starting at index 0)
     */
    public void update(byte[] data, int len) {
        int j = this.pt;
        for (int i = 0; i < len; i++) {
            this.b[j++] ^= data[i];
            if (j >= this.rsiz) {
                sha3_keccakf(b);
                j = 0;
            }
        }
        this.pt = j;
    }

    /**
     * Switch from absorbing to extensible squeezing.
     */
    public void xof() {
        if (kmac) {
            update(right_encode_0, right_encode_0.length); // mandatory padding as per the NIST specification
        }
        // the (binary) cSHAKE suffix is 00, while the (binary) Model.SHAKE suffix is 1111
        this.b[this.pt] ^= (byte)(this.ext ? 0x04 : 0x1F);
        this.b[this.rsiz - 1] ^= (byte)0x80;
        sha3_keccakf(b);
        this.pt = 0;
    }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Repeat as many times as needed to extract the total desired number of bytes.
     * @param out   hash value buffer
     * @param len   squeezed byte count
     */
    public void out(byte[] out, int len) {
        int j = pt;
        for (int i = 0; i < len; i++) {
            if (j >= rsiz) {
                sha3_keccakf(b);
                j = 0;
            }
            out[i] = b[j++];
        }
        pt = j;
    }

    /**
     * Compute the streamlined cSHAKE256 on input X with output bitlength L, function name N, and customization string S.
     *
     * @param X     data to be hashed
     * @param L     desired output length in bits
     * @param N     function name
     * @param S     customization string
     * @return  the desired hash value.
     */
    static byte[] cSHAKE256(byte[] X, int L, byte[] N, byte[] S) {
        // Validity Conditions: len(N) < 2^2040 and len(S) < 2^2040
        if ((L & 7) != 0) {
            throw new RuntimeException("Implementation restriction: output length (in bits) must be a multiple of 8");
        }
        byte[] val = new byte[L >>> 3];
        SHAKE shake = new SHAKE();
        shake.cinit256(N, S);
        shake.update(X, X.length);
        shake.xof();
        shake.out(val, L >>> 3);
        return val; // SHAKE256(X, L) or KECCAK512(prefix || X || 00, L)
    }

    /**
     * Compute the streamlined KMACXOF256 with key K on input X, with output bitlength L and customization string S.
     *
     * @param K     MAC key
     * @param X     data to be hashed
     * @param L     desired output length in bits
     * @param S     customization string
     * @return  the desired MAC tag
     */
    public static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
        // Validity Conditions: len(K) < 2^2040 and 0 ≤ L and len(S) < 2^2040
        if ((L & 7) != 0) {
            throw new RuntimeException("Implementation restriction: output length (in bits) must be a multiple of 8");
        }
        byte[] val = new byte[L >>> 3];
        SHAKE shake = new SHAKE();
        shake.kinit256(K, S);
        shake.update(X, X.length);
        shake.xof();
        shake.out(val, L >>> 3);
        return val; // SHAKE256(X, L) or KECCAK512(prefix || X || 00, L)
    }

}

