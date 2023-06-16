
import java.util.Arrays;

public class ISAP128AEAD {
    // ISAP 128 & ASCON

    private static final String CRYPTO_VERSION = "2.0.1";
    private static final int CRYPTO_KEYBYTES = 16;
    private static final int CRYPTO_NSECBYTES = 0;
    private static final int CRYPTO_NPUBBYTES = 16;
    private static final int CRYPTO_ABYTES = 16;
    private static final int CRYPTO_NOOVERLAP = 1;

    /// Rate in bits
    private static final int ISAP_rH = 64;
    private static final int ISAP_rB = 1;

    // Number of rounds  Isap-128 & Ascon
    private static final int ISAP_sH = 12;
    private static final int ISAP_sB = 12;
    private static final int ISAP_sE = 12;
    private static final int ISAP_sK = 12;

    // State size in bytes
    private static final int ISAP_STATE_SZ = 40;

    private static final int ISAP_K = 128;
    private static final int ISAP_rH_SZ = (ISAP_rH + 7) / 8;
    private static final int ISAP_IV_SZ = 8;
    private static final int ISAP_TAG_SZ = 16;

    private static final int[] ISAP_IV_A = {
        0x01, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK};
    private static final int[] ISAP_IV_KA = {
        0x02, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK};
    private static final int[] ISAP_IV_KE = {
        0x03, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK};

    // ASCON-reference.c

    public static long ROTR(long x, int n) {
        return Long.rotateRight(x, n);
    }

    public static long load64(int[] S) {
        long result = 0;
        for (int i = 0; i < 8; ++i) {
            result |= ((long) S[i] & 0xFF) << (56 - i * 8);
        }
        return result;
    }

    public static void store64(int[] S, int offset, long x) {
        for (int i = 0; i < 8; ++i) {
            S[i + offset] = (int) (x >>> (56 - i * 8)) & 0xFF;
        }
    }

    public static void PermutationInitialize(int[] S) {
        Arrays.fill(S, 0);
    }

    public static void PermutationAddBytes(int[] state, int[] data, int offset, int length) {
        assert offset < 40;
        assert offset + length <= 40;
        for (int i = 0; i < length; i++) {
            state[offset + i] ^= data[i];
        }
    }

    public static void PermutationOverwriteBytes(int[] state, int[] data, int offset, int length) {
        assert offset < 40;
        assert offset + length <= 40;
        for (int i = 0; i < length; i++) {
            state[offset + i] = data[i];
        }
    }

    static void PermutationPermuteNrounds(int S[], int rounds) {
        long i;
        long x0 = 0, x1 = 0, x2 = 0, x3 = 0, x4 = 0;
        long t0, t1, t2, t3, t4;

        x0 = load64(Arrays.copyOfRange(S, 0, 8));
        x1 = load64(Arrays.copyOfRange(S, 8, 16));
        x2 = load64(Arrays.copyOfRange(S, 16, 24));
        x3 = load64(Arrays.copyOfRange(S, 24, 32));
        x4 = load64(Arrays.copyOfRange(S, 32, 40));

        for (i = 12 - rounds; i < 12; ++i) {
            // addition of round constant
            x2 ^= (((long) (0xf) - i) << 4) | i;
            // substitution layer
            x0 ^= x4;
            x4 ^= x3;
            x2 ^= x1;
            t0 = x0;
            t1 = x1;
            t2 = x2;
            t3 = x3;
            t4 = x4;
            t0 = ~t0;
            t1 = ~t1;
            t2 = ~t2;
            t3 = ~t3;
            t4 = ~t4;
            t0 &= x1;
            t1 &= x2;
            t2 &= x3;
            t3 &= x4;
            t4 &= x0;
            x0 ^= t1;
            x1 ^= t2;
            x2 ^= t3;
            x3 ^= t4;
            x4 ^= t0;
            x1 ^= x0;
            x0 ^= x4;
            x3 ^= x2;
            x2 = ~x2;
            // linear diffusion layer
            x0 ^= ROTR(x0, 19) ^ ROTR(x0, 28);
            x1 ^= ROTR(x1, 61) ^ ROTR(x1, 39);
            x2 ^= ROTR(x2, 1) ^ ROTR(x2, 6);
            x3 ^= ROTR(x3, 10) ^ ROTR(x3, 17);
            x4 ^= ROTR(x4, 7) ^ ROTR(x4, 41);
        }
        store64(S, 0, x0);
        store64(S, 8, x1);
        store64(S, 16, x2);
        store64(S, 24, x3);
        store64(S, 32, x4);
    }

    public static void PermutationExtractBytes(int[] state, int[] data, int offset, int length) {
        assert offset < 40;
        assert offset + length <= 40;
        System.arraycopy(state, offset, data, 0, length);
    }

    public static void isap_rk(int[] k, int[] iv, int[] in, long inlen, int[] out, int outlen) {
        // Init State
        int[] state = new int[ISAP_STATE_SZ];
        PermutationInitialize(state);
        PermutationAddBytes(state, k, 0, CRYPTO_KEYBYTES);
        PermutationAddBytes(state, iv, CRYPTO_KEYBYTES, ISAP_IV_SZ);
        // System.out.println("Before -- : STATE: " + Arrays.toString(state));
        PermutationPermuteNrounds(state, ISAP_sK);

        // System.out.println("STATE: " + Arrays.toString(state));
        //  Absorb
        for (long i = 0; i < inlen * 8 - 1; i++) {
            long cur_byte_pos = i / 8;
            long cur_bit_pos = 7 - (i % 8);
            int cur_bit = ((in[(int) cur_byte_pos] >>> (int) cur_bit_pos) & 0x01) << 7;
            PermutationAddBytes(state, new int[] {cur_bit}, 0, 1);
            PermutationPermuteNrounds(state, ISAP_sB);
        }
        int cur_bit = ((in[(int) (inlen - 1)]) & 0x01) << 7;
        PermutationAddBytes(state, new int[] {cur_bit}, 0, 1);
        PermutationPermuteNrounds(state, ISAP_sK);

        // Squeeze K*
        PermutationExtractBytes(state, out, 0, outlen);
    }

    public static void isap_mac(
        int[] k, int[] npub, int[] ad, long adlen, int[] c, long clen, int[] tag) {
        // Init State
        int[] state = new int[ISAP_STATE_SZ];
        PermutationInitialize(state);
        PermutationAddBytes(state, npub, 0, CRYPTO_NPUBBYTES);
        PermutationAddBytes(state, ISAP_IV_A, CRYPTO_NPUBBYTES, ISAP_IV_SZ);
        PermutationPermuteNrounds(state, ISAP_sH);

        // Absorb AD
        int rate_bytes_avail = ISAP_rH_SZ;
        int[] cur_ad;
        for (long i = 0; i < adlen; i++) {
            if (rate_bytes_avail == 0) {
                PermutationPermuteNrounds(state, ISAP_sH);
                rate_bytes_avail = ISAP_rH_SZ;
            }
            cur_ad = new int[] {ad[(int) i]};
            PermutationAddBytes(state, cur_ad, ISAP_rH_SZ - rate_bytes_avail, 1);
            rate_bytes_avail--;
        }

        // Absorb Padding: 0x80
        if (rate_bytes_avail == 0) {
            PermutationPermuteNrounds(state, ISAP_sH);
            rate_bytes_avail = ISAP_rH_SZ;
        }
        int[] pad = new int[] {0x80};
        PermutationAddBytes(state, pad, ISAP_rH_SZ - rate_bytes_avail, 1);
        PermutationPermuteNrounds(state, ISAP_sH);

        // Domain Separation: 0x01
        int[] dom_sep = new int[] {0x01};
        PermutationAddBytes(state, dom_sep, ISAP_STATE_SZ - 1, 1);

        // Absorb C
        rate_bytes_avail = ISAP_rH_SZ;
        int[] cur_c;
        for (long i = 0; i < clen; i++) {
            cur_c = new int[] {c[(int) i]};
            PermutationAddBytes(state, cur_c, ISAP_rH_SZ - rate_bytes_avail, 1);
            rate_bytes_avail--;
            if (rate_bytes_avail == 0) {
                PermutationPermuteNrounds(state, ISAP_sH);
                rate_bytes_avail = ISAP_rH_SZ;
            }
        }

        pad = new int[] {0x80};
        PermutationAddBytes(state, pad, ISAP_rH_SZ - rate_bytes_avail, 1);
        PermutationPermuteNrounds(state, ISAP_sH);

        // Derive Ka*
        int[] y = new int[CRYPTO_KEYBYTES];
        int[] ka_star = new int[CRYPTO_KEYBYTES];
        PermutationExtractBytes(state, y, 0, CRYPTO_KEYBYTES);
        isap_rk(k, ISAP_IV_KA, y, CRYPTO_KEYBYTES, ka_star, CRYPTO_KEYBYTES);

        // Squeezing Tag
        PermutationOverwriteBytes(state, ka_star, 0, CRYPTO_KEYBYTES);
        PermutationPermuteNrounds(state, ISAP_sH);
        PermutationExtractBytes(state, tag, 0, CRYPTO_KEYBYTES);
    }

    public static void isap_enc(
        final int[] k, final int[] npub, final int[] m, final long mlen, int[] c) {
        // Derive Ke*
        int[] state = new int[ISAP_STATE_SZ];
        isap_rk(k, ISAP_IV_KE, npub, CRYPTO_NPUBBYTES, state, (ISAP_STATE_SZ - CRYPTO_NPUBBYTES));
        PermutationOverwriteBytes(
            state, npub, (ISAP_STATE_SZ - CRYPTO_NPUBBYTES), CRYPTO_NPUBBYTES);

        // Squeeze Keystream
        int key_bytes_avail = 0;
        for (long i = 0; i < mlen; i++) {
            if (key_bytes_avail == 0) {
                PermutationPermuteNrounds(state, ISAP_sE);
                key_bytes_avail = ISAP_rH_SZ;
            }
            int[] keybyte = new int[1];
            PermutationExtractBytes(state, keybyte, (int) i % ISAP_rH_SZ, 1);

            c[(int) i] = m[(int) i] ^ keybyte[0];
            key_bytes_avail--;
        }
    }

    public static int crypto_aead_encrypt(int[] c, long[] clen, int[] m, long mlen, int[] ad,
        long adlen, int[] nsec, int[] npub, int[] k) {
        // Ciphertext length is mlen + tag length
        clen[0] = mlen + ISAP_TAG_SZ;

        // Encrypt plaintext
        if (mlen > 0) {
            isap_enc(k, npub, m, mlen, c);
        }

        // Generate tag
        int[] tag = new int[16];
        isap_mac(k, npub, ad, adlen, c, mlen, tag);
        for (int i = 0; i < tag.length; i++) c[i + (int) mlen] = tag[i];
        return 0;
    }

    public static int crypto_aead_decrypt(int[] m, long[] mlen, int[] nsec, int[] c, long clen,
        int[] ad, long adlen, int[] npub, int[] k) {
        mlen[0] = clen - ISAP_TAG_SZ;

        int[] tag = new int[ISAP_TAG_SZ];
        isap_mac(k, npub, ad, adlen, c, mlen[0], tag);

        for (int i = 0; i < ISAP_TAG_SZ; i++) {
            if (tag[i] != c[(int) mlen[0] + i]) {
                System.out.println("Tag verification failed");
                return -1;
            }
        }

        if (mlen[0] > 0) {
            isap_enc(k, npub, c, mlen[0], m);
        }

        return 0;
    }

    public static void main(String[] args) {
        int[] m = new int[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
        // int[] m = new int[1000];
        // for (int i = 0; i < m.length; i++) m[i] = i;
        int[] c = new int[m.length + 16];
        long[] clen = new long[] {0};
        long mlen = m.length;
        int[] ad = new int[] {3, 4, 5};
        long adlen = 3;
        int[] nsec = new int[] {};

        int[] npub = new int[16];
        for (int i = 0; i < 16; i++) npub[i] = i;
        int[] key = new int[16];
        for (int i = 0; i < 16; i++) key[i] = i;
        System.out.println("original: " + Arrays.toString(m));
        crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, null, npub, key);

        System.out.println("Encrypted: " + Arrays.toString(c));

        int[] dec = new int[m.length];
        /*public static int crypto_aead_decrypt(
        int[] m, long[] mlen, int[] nsec, int[] c, long clen,
        int[] ad, long adlen, int[] npub, int[] k
    ) */
        long[] dec_len = new long[1];
        crypto_aead_decrypt(dec, dec_len, null, c, clen[0], ad, adlen, npub, key);
        System.out.println("Decrypted: " + Arrays.toString(dec));
    }
}