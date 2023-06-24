
import java.lang.Integer;
import java.util.Arrays;

public class GIFT128 {
    private static final int TAGBYTES = 16;
    private static final boolean COFB_ENCRYPT = true;
    private static final boolean COFB_DECRYPT = false;

    public static final int[] GIFT_RC = {0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
        0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30, 0x21,
        0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A};

    public static long rowperm(int S, int B0_pos, int B1_pos, int B2_pos, int B3_pos) {
        int T = 0;
        int b;
        for (b = 0; b < 8; b++) {
            T |= ((S >> (4 * b + 0)) & 0x1) << (b + 8 * B0_pos);
            T |= ((S >> (4 * b + 1)) & 0x1) << (b + 8 * B1_pos);
            T |= ((S >> (4 * b + 2)) & 0x1) << (b + 8 * B2_pos);
            T |= ((S >> (4 * b + 3)) & 0x1) << (b + 8 * B3_pos);
        }

        return Integer.toUnsignedLong(T);
    }

    public static void giftb128(int[] P, int[] K, int[] C) {
        int round;

        long[] S = new long[4];
        long T;
        int[] W = new int[8];
        int T6, T7;

        int s0 = (P[0] << 24) | (P[1] << 16) | (P[2] << 8) | P[3];
        S[0] = Integer.toUnsignedLong((int) s0);

        int s1 = (P[4] << 24) | (P[5] << 16) | (P[6] << 8) | P[7];
        S[1] = Integer.toUnsignedLong(s1);

        int s2 = (P[8] << 24) | (P[9] << 16) | (P[10] << 8) | P[11];
        S[2] = Integer.toUnsignedLong(s2);

        int s3 = (P[12] << 24) | (P[13] << 16) | (P[14] << 8) | P[15];
        S[3] = Integer.toUnsignedLong(s3);

     

        W[0] = ((byte) K[0] << 8) | (byte) K[1];
        W[1] = ((byte) K[2] << 8) | (byte) K[3];
        W[2] = ((byte) K[4] << 8) | (byte) K[5];
        W[3] = ((byte) K[6] << 8) | (byte) K[7];
        W[4] = ((byte) K[8] << 8) | (byte) K[9];
        W[5] = ((byte) K[10] << 8) | (byte) K[11];
        W[6] = ((byte) K[12] << 8) | (byte) K[13];
        W[7] = ((byte) K[14] << 8) | (byte) K[15];
    

        for (round = 0; round < 40; round++) {
            S[1] ^= S[0] & S[2];
            S[0] ^= S[1] & S[3];
            S[2] ^= S[0] | S[1];
            S[3] ^= S[2];
            S[1] ^= S[3];
            S[3] ^= 0xffffffffL;
            S[2] ^= S[0] & S[1];

            T = S[0];
            S[0] = S[3];
            S[3] = T;

            S[0] = rowperm((int) S[0], 0, 3, 2, 1);
            S[1] = rowperm((int) S[1], 1, 0, 3, 2);
            S[2] = rowperm((int) S[2], 2, 1, 0, 3);
            S[3] = rowperm((int) S[3], 3, 2, 1, 0);

            S[2] ^= Integer.toUnsignedLong(W[2] << 16 | W[3]);
            S[1] ^= Integer.toUnsignedLong(W[6] << 16 | W[7]);

            /*Add round constant*/
            S[3] ^= 0x80000000L ^ GIFT_RC[round];

            /*===Key state update===*/
            T6 = ((W[6] >>> 2) & 0xFFFF) | ((W[6] << 14) & 0xFFFF);
            T7 = ((W[7] >>> 12) & 0xFFFF) | ((W[7] << 4) & 0xFFFF);
            W[7] = W[5];
            W[6] = W[4];
            W[5] = W[3];
            W[4] = W[2];
            W[3] = W[1];
            W[2] = W[0];
            W[1] = T7;
            W[0] = T6;

           
        }

        C[0] = (int) (S[0] >>> 24) & 0xFF;
        C[1] = (int) (S[0] >>> 16) & 0xFF;
        C[2] = ((int) S[0] >> 8) & 0xFF;
        C[3] = (int) S[0] & 0xFF;
        C[4] = ((int) S[1] >> 24) & 0xFF;
        ;
        C[5] = ((int) S[1] >> 16) & 0xFF;
        C[6] = ((int) S[1] >> 8) & 0xFF;
        C[7] = (int) S[1] & 0xFF;
        C[8] = ((int) S[2] >> 24) & 0xFF;
        C[9] = ((int) S[2] >> 16) & 0xFF;
        C[10] = ((int) S[2] >> 8) & 0xFF;
        C[11] = (int) S[2] & 0xFF;
        C[12] = ((int) S[3] >> 24) & 0xFF;
        C[13] = ((int) S[3] >> 16) & 0xFF;
        C[14] = ((int) S[3] >> 8) & 0xFF;
        C[15] = (int) S[3] & 0xFF;
    }

    public static void padding(int[] d, int[] s, int s_index, int no_of_bytes) {
        int i;
        int[] tmp = new int[16];
        if (no_of_bytes == 0) {
            for (i = 0; i < 16; i++) tmp[i] = 0;
            tmp[0] = 0x80;
        } else if (no_of_bytes < 16) {
            for (i = 0; i < no_of_bytes; i++) tmp[i] = s[i + s_index];
            tmp[no_of_bytes] = 0x80;
            for (i = no_of_bytes + 1; i < 16; i++) tmp[i] = 0;
        } else {
            for (i = 0; i < 16; i++) tmp[i] = s[i + s_index];
        }
        for (i = 0; i < 16; i++) d[i] = tmp[i];
    }

    public static void xor_block(
        int[] d, int d_index, int[] s1, int[] s2, int s2_index, int no_of_bytes) {
        int i;
        for (i = 0; i < no_of_bytes; i++) d[i + d_index] = s1[i] ^ s2[i + s2_index];
    }

    public static void xor_topbar_block(int[] d, int[] s1, int[] s2) {
        int i;
        int[] tmp = new int[16];
        for (i = 0; i < 8; i++) tmp[i] = s1[i] ^ s2[i];
        for (i = 8; i < 16; i++) tmp[i] = s1[i];

        for (i = 0; i < 16; i++) d[i] = tmp[i];
    }

    public static void double_half_block(int[] d, int[] s) {
        int i;
        int[] tmp = new int[8];
        /*x^{64} + x^4 + x^3 + x + 1*/
        for (i = 0; i < 7; i++) tmp[i] = ((s[i] << 1) & 0xFF) | ((s[i + 1] >>> 7) & 0xFF);
        tmp[7] = ((s[7] << 1) & 0xFF) ^ (((s[0] >> 7) * 27) & 0xFF);

        for (i = 0; i < 8; i++) d[i] = tmp[i];
    }

    public static void triple_half_block(int[] d, int[] s) {
        int i;
        int[] tmp = new int[8];
        double_half_block(tmp, s);
        for (i = 0; i < 8; i++) d[i] = s[i] ^ tmp[i];
    }

    public static void G(int[] d, int[] s) {
        int[] tmp = new int[16];

        // Y[1],Y[2] -> Y[2],Y[1]<<<1
        for (int i = 0; i < 8; i++) {
            tmp[i] = s[8 + i];
        }
        for (int i = 0; i < 7; i++) {
            tmp[i + 8] = ((s[i] << 1) & 0xFF) | ((s[i + 1] >>> 7) & 0xFF);
        }
        tmp[7 + 8] = ((s[7] << 1) & 0xFF) | ((s[0] >>> 7) & 0xFF);

        for (int i = 0; i < 16; i++) {
            d[i] = tmp[i];
        }
    }

    public static void pho1(int[] d, int[] Y, int[] M, int M_index, int no_of_bytes) {
        int[] tmpM = new int[16];
        G(Y, Y);
        padding(tmpM, M, M_index, no_of_bytes);
        xor_block(d, 0, Y, tmpM, 0, 16);
    }

    public static void pho(
        int[] Y, int[] M, int M_index, int[] X, int[] C, int C_index, int no_of_bytes) {
        xor_block(C, C_index, Y, M, M_index, no_of_bytes);
        pho1(X, Y, M, M_index, no_of_bytes);
    }

    public static void phoprime(
        int[] Y, int[] C, int C_index, int[] X, int[] M, int M_index, int no_of_bytes) {
        xor_block(M, M_index, Y, C, C_index, no_of_bytes);
        pho1(X, Y, M, M_index, no_of_bytes);
    }

    public static int cofb_crypt(
        int[] out, int[] k, int[] n, int[] a, int alen, int[] in, int inlen, boolean encrypting) {
        int i;
        int emptyA, emptyM;
        int a_index = 0;
        int in_index = 0;
        int out_index = 0;

        if (!encrypting) {
            if (inlen < TAGBYTES)
                return -1;
            inlen -= TAGBYTES;
        }

        if (alen == 0)
            emptyA = 1;
        else
            emptyA = 0;

        if (inlen == 0)
            emptyM = 1;
        else
            emptyM = 0;

        // Mask-Gen
        int[] Y = new int[16];
        int[] input = new int[16];
        int[] offset = new int[8];

        // Nonce is 128-bit
        for (i = 0; i < 16; i++) input[i] = n[i];

        giftb128(input, k, Y);
        for (i = 0; i < 8; i++) offset[i] = Y[i];

        

        // Process AD (Additional Data)
        // Non-empty A (full blocks)
        while (alen > 16) {
            // X[i] = (A[i] + G(Y[i-1])) + offset
            pho1(input, Y, a, a_index, 16);
            // offset = 2 * offset
            double_half_block(offset, offset);
            xor_topbar_block(input, input, offset);
            // Y[i] = E(X[i])
            giftb128(input, k, Y);

            a_index = a_index + 16;
            alen -= 16;
        }

        // Last block
        // Full block: offset = 3 * offset
        // Partial block: offset = 3^2 * offset
        triple_half_block(offset, offset);
        if ((alen % 16 != 0) || (emptyA != 0)) {
            triple_half_block(offset, offset);
        }

        if (emptyM == 1) {
            // Empty M: offset = 3^2 * offset
            triple_half_block(offset, offset);
            triple_half_block(offset, offset);
        }

        // X[i] = (pad(A[i]) + G(Y[i-1])) + offset
        pho1(input, Y, a, a_index, alen);

        xor_topbar_block(input, input, offset);
        // Y[a] = E(X[a])
        giftb128(input, k, Y);

        // Process M
        // Full blocks
        while (inlen > 16) {
            double_half_block(offset, offset);
            // C[i] = Y[i+a-1] + M[i]
            // X[i] = M[i] + G(Y[i+a-1]) + offset
            if (encrypting) {
                pho(Y, in, in_index, input, out, out_index, 16);

            } else {
                phoprime(Y, in, in_index, input, out, out_index, 16);
            }

            xor_topbar_block(input, input, offset);
            // Y[i] = E(X[i+a])
            giftb128(input, k, Y);

            in_index = in_index + 16;
            out_index = out_index + 16;
            inlen -= 16;
        }

        if (emptyM != 1) {
            // Full block: offset = 3 * offset
            // Empty data / partial block: offset = 3^2 * offset
            triple_half_block(offset, offset);
            if (inlen % 16 != 0) {
                triple_half_block(offset, offset);
            }

            // Last block
            // C[m] = Y[m+a-1] + M[m]
            // X[a+m] = M[m] + G(Y[m+a-1]) + offset
            if (encrypting) {
                pho(Y, in, in_index, input, out, out_index, inlen);
                // System.out.println(Arrays.toString(out));
                out_index += inlen;
            } else {
                phoprime(Y, in, in_index, input, out, out_index, inlen);
                in_index += inlen;
            }

            xor_topbar_block(input, input, offset);
            // T = E(X[m+a])
            giftb128(input, k, Y);
        }

        if (encrypting) {
            // Copy the tag to the output
            System.arraycopy(Y, 0, out, out_index, TAGBYTES);
            return 0;
        } else {
            // Check for validity
            int[] tag = new int[TAGBYTES];
            System.arraycopy(in, in_index, tag, 0, TAGBYTES);
            return Arrays.equals(tag, Y) ? 0 : -1;
        }
    }

    public static int crypto_aead_encrypt(int[] c, int[] clen, int[] m, int mlen, int[] ad,
        int adlen, int[] nsec, int[] npub, int[] k) {
        clen[0] = mlen + TAGBYTES;
        return cofb_crypt(c, k, npub, ad, adlen, m, mlen, COFB_ENCRYPT);
    }

    public static int crypto_aead_decrypt(int[] m, int[] mlen, int[] nsec, int[] c, int clen,
        int[] ad, int adlen, int[] npub, int[] k) {
        mlen[0] = clen - TAGBYTES;
        return cofb_crypt(m, k, npub, ad, adlen, c, clen, COFB_DECRYPT);
    }

    public static void main(String[] args) {
        /*int[] P = new int[16];
        for (int i = 0; i < 16; i++) P[i] = i;

        int[] K = new int[16];
        for (int i = 15; i > 0; i--) K[i] = i;

        int[] C = new int[16];
        Arrays.fill(C, 0);
        giftb128(P, K, C);
        System.out.println(Arrays.toString(C));
        System.out.println(rowperm(1234567, 4335, 4324, 2321, 3422));*/

        int[] d = new int[] {255, 255, 255, 255, 255, 255, 255, 255};
        int[] s = new int[] {255, 255, 255, 255, 255, 255, 255, 255};
        double_half_block(d, s);
        // System.out.println(Arrays.toString(d));

        int[] d2 = new int[16];
        Arrays.fill(d2, 250);

        int[] s2 = new int[16];
        Arrays.fill(s2, 150);
        G(d2, s2);
        // System.out.println(Arrays.toString(d2));

        /* crypto_aead_encrypt(int[] c, int[] clen, int[] m, int mlen, int[] ad, int adlen, int[]
         * nsec, int[] npub, int[] k)*/

        int[] m = new int[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        System.out.println("Original: " + Arrays.toString(m));
        int mlen = m.length;
        int[] c = new int[mlen + 16];
        int[] clen = new int[1];
        int[] ad = new int[] {10, 20, 30, 30, 40};
        int adlen = ad.length;
        int[] npub = new int[16];
        for (int i = 0; i < 16; i++) npub[i] = i;
        int[] key = new int[16];
        for (int i = 0; i < 16; i++) key[i] = i;
        crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, null, npub, key);
        System.out.println("Encrypted: " + Arrays.toString(c));

        int[] dec = new int[mlen];
        int[] dec_len = new int[1];
        crypto_aead_decrypt(dec, dec_len, null, c, clen[0], ad, adlen, npub, key);
        System.out.println("Decrypted: " + Arrays.toString(dec));
    }
}