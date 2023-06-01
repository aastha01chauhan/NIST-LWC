package org.example;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class RomulusT {

    private static int COUNTER_LENGTH = 7;
    private static int MEMBER_MASK = 64;
    private static final int NB_ROUNDS = 40;
    private static final int TWEAK_LENGTH = 48;

    private static final int[] sbox_8 = { 0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a, 0x53,
            0x73, 0x5b, 0x7b, 0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b, 0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99,
            0x2b, 0xe5, 0xcc, 0xe8, 0xc1, 0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9, 0xa5,
            0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b, 0xb9, 0x32, 0x88, 0x3c,
            0x85, 0x8d, 0x34, 0x84, 0x3d, 0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d, 0x62, 0x4a, 0x6c, 0x45, 0x4d,
            0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d, 0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14,
            0xad, 0x02, 0xb1, 0x0c, 0xbc, 0x04, 0xb4, 0x0d, 0xbd, 0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed, 0xd1,
            0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd, 0x36, 0x8e, 0x38, 0x82, 0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a,
            0x28, 0x93, 0x20, 0x9b, 0x29, 0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78, 0x50,
            0x70, 0x59, 0x79, 0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab, 0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09,
            0xbb, 0xe6, 0xce, 0xea, 0xc2, 0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb, 0x31,
            0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f, 0x2f, 0x61, 0x48, 0x6e,
            0x46, 0x4f, 0x67, 0x47, 0x6f, 0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f, 0xa2, 0x18, 0xae, 0x16, 0x1f,
            0xa7, 0x17, 0xaf, 0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf, 0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7,
            0xef, 0xd2, 0xf2, 0xde, 0xfe, 0xd7, 0xf7, 0xdf, 0xff };

    private static final int[] TWEAKEY_P = { 9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7 };

    private static final int[] RC = { 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F, 0x1E, 0x3C, 0x39,
            0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C,
            0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A };

    private static final int[] LFSR_8_TK2 = {0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 65, 67, 69, 71, 73, 75, 77, 79, 81, 83, 85, 87, 89, 91, 93, 95, 97, 99, 101, 103, 105, 107, 109, 111, 113, 115, 117, 119, 121, 123, 125, 127, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 193, 195, 197, 199, 201, 203, 205, 207, 209, 211, 213, 215, 217, 219, 221, 223, 225, 227, 229, 231, 233, 235, 237, 239, 241, 243, 245, 247, 249, 251, 253, 255, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47, 49, 51, 53, 55, 57, 59, 61, 63, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 129, 131, 133, 135, 137, 139, 141, 143, 145, 147, 149, 151, 153, 155, 157, 159, 161, 163, 165, 167, 169, 171, 173, 175, 177, 179, 181, 183, 185, 187, 189, 191, 192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222, 224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254};
    private static final int[] LFSR_8_TK3 = {0, 128, 1, 129, 2, 130, 3, 131, 4, 132, 5, 133, 6, 134, 7, 135, 8, 136, 9, 137, 10, 138, 11, 139, 12, 140, 13, 141, 14, 142, 15, 143, 16, 144, 17, 145, 18, 146, 19, 147, 20, 148, 21, 149, 22, 150, 23, 151, 24, 152, 25, 153, 26, 154, 27, 155, 28, 156, 29, 157, 30, 158, 31, 159, 160, 32, 161, 33, 162, 34, 163, 35, 164, 36, 165, 37, 166, 38, 167, 39, 168, 40, 169, 41, 170, 42, 171, 43, 172, 44, 173, 45, 174, 46, 175, 47, 176, 48, 177, 49, 178, 50, 179, 51, 180, 52, 181, 53, 182, 54, 183, 55, 184, 56, 185, 57, 186, 58, 187, 59, 188, 60, 189, 61, 190, 62, 191, 63, 64, 192, 65, 193, 66, 194, 67, 195, 68, 196, 69, 197, 70, 198, 71, 199, 72, 200, 73, 201, 74, 202, 75, 203, 76, 204, 77, 205, 78, 206, 79, 207, 80, 208, 81, 209, 82, 210, 83, 211, 84, 212, 85, 213, 86, 214, 87, 215, 88, 216, 89, 217, 90, 218, 91, 219, 92, 220, 93, 221, 94, 222, 95, 223, 224, 96, 225, 97, 226, 98, 227, 99, 228, 100, 229, 101, 230, 102, 231, 103, 232, 104, 233, 105, 234, 106, 235, 107, 236, 108, 237, 109, 238, 110, 239, 111, 240, 112, 241, 113, 242, 114, 243, 115, 244, 116, 245, 117, 246, 118, 247, 119, 248, 120, 249, 121, 250, 122, 251, 123, 252, 124, 253, 125, 254, 126, 255, 127};


    private static void increase_counter(int[] counter) {
        int mask;
        if ((counter[COUNTER_LENGTH - 1] & 0x80) != 0)
            mask = 0x95;
        else
            mask = 0x00;

        for (int i = COUNTER_LENGTH - 1; i >= 1; i--) {
            counter[i] = (((counter[i] << 1) & 0xFE) ^ (counter[i - 1] >> 7));
        }
        counter[0] = (((counter[0] << 1) & 0xFE) ^ mask);
    }

    public static List<List<Integer>> parse(List<Integer> L_in, int x) {
        List<List<Integer>> L_out = new ArrayList<>();
        int cursor = 0;

        while (L_in.size() - cursor >= x) {
            L_out.add(L_in.subList(cursor, cursor + x));
            cursor += x;
        }

        if (L_in.size() - cursor > 0) {
            L_out.add(L_in.subList(cursor, L_in.size()));
        }

        if (L_in.isEmpty()) {
            L_out.add(new ArrayList<>());
        }

        L_out.add(0, new ArrayList<>());
        return L_out;
    }

    private static int[] ipad_star(int[] x, int pad_length) {
        if (x.length == 0) {
            return x;
        }
        int[] result = new int[x.length + pad_length - (x.length % pad_length)];
        System.arraycopy(x, 0, result, 0, x.length);
        Arrays.fill(result, x.length + 1, result.length, 0);;
        result[result.length-1] = x.length % pad_length;
        return result;
    }

    public static int[] tk_encoding(int[] counter, int b, int[] t, int[] k) {

        int[] encoded = new int[counter.length + 1 + 8 + t.length + k.length];
        System.arraycopy(counter, 0, encoded, 0, counter.length);
        encoded[counter.length] = (byte) (b ^ MEMBER_MASK);
        Arrays.fill(encoded, counter.length + 1, counter.length + 1 + 8,  0);
        System.arraycopy(t, 0, encoded, counter.length + 1 + 8, t.length);
        System.arraycopy(k, 0, encoded, counter.length + 1 + 8 + t.length, k.length);
        return encoded;
    }

    public static int[] concat(int[]... arrays) {
        int totalLength = 0;
        for (int[] array : arrays) {
            totalLength += array.length;
        }
        int[] result = new int[totalLength];
        int currentIndex = 0;
        for (int[] array : arrays) {
            System.arraycopy(array, 0, result, currentIndex, array.length);
            currentIndex += array.length;
        }
        return result;
    }

    private static int[] listToArray(List<Integer> list) {
        int[] array = new int[list.size()];
        for (int i = 0; i < list.size(); i++) {
            array[i] = list.get(i);
        }
        return array;
    }

    private static int[] concatenateArrays(int[] arr1, int[] arr2) {
        int[] result = new int[arr1.length + arr2.length];
        System.arraycopy(arr1, 0, result, 0, arr1.length);
        System.arraycopy(arr2, 0, result, arr1.length, arr2.length);
        return result;
    }

    public static int[] skinny_enc(int[] plaintext, int[] tweakey) {

        // Initialize tk[0] to the values in the tweakey array
        int[][] tk = new int[NB_ROUNDS + 1][TWEAK_LENGTH];

        // Initialize tk[0] to the values in the tweakey array
        for (int i = 0; i < TWEAK_LENGTH; i++) {
            tk[0][i] = tweakey[i];
            tk[0][i] = (tk[0][i] & 0xff);
        }

        // Initialize s to the first 16 bytes of the plaintext array
        int[] s = new int[16];
        for (int i = 0; i < 16; i++) {
            s[i] = (int) plaintext[i];
        }

        int[] s1 = new int[16];

        for (int i = 0; i < NB_ROUNDS-1; i++) {
            System.arraycopy(tk[i], 0, tk[i+1], 0, TWEAK_LENGTH);
            for (int j = 0; j < TWEAK_LENGTH; j++) {
                tk[i+1][j] = tk[i][j-j%16+TWEAKEY_P[j%16]];
            }
            for (int j = 0; j < 8; j++) {
                tk[i+1][j+16] = (int) LFSR_8_TK2[tk[i+1][j+16] & 0xff];
                tk[i+1][j+32] = (int) LFSR_8_TK3[tk[i+1][j+32] & 0xff];
            }
        }


        for (int i = 0; i < NB_ROUNDS; i++) {
            for (int j = 0; j < 16; j++) {
                s1[j] = (sbox_8[s[j]] & 0xff);
            }

            s1[0] ^= RC[i] & 0xf;
            s1[4] ^= (RC[i]>>4) & 0xf;
            s1[8] ^= 0x2;

            for (int j = 0; j < 8; j++) {
                s1[j] ^= (tk[i][j] ^ tk[i][j+16] ^ tk[i][j+32]);
            }

            int temp = s1[7];
            s1[7] = s1[6];
            s1[6] = s1[5];
            s1[5] = s1[4];
            s1[4] = temp;

            temp = s1[8];
            s1[8] = s1[10];
            s1[10] = temp;

            temp = s1[9];
            s1[9] = s1[11];
            s1[11] = temp;

            temp = s1[12];
            s1[12] = s1[13];
            s1[13] = s1[14];
            s1[14] = s1[15];
            s1[15] = temp;

            for (int j = 0; j < 4; j++) {
                int temp1 = s1[j] ^ s1[8 + j] ^ s1[12 + j];
                int temp2 = s1[j];
                int temp3 = s1[4 + j] ^ s1[8 + j];
                int temp4 = s1[j] ^ s1[8 + j];

                s1[j] = temp1;
                s1[4 + j] = temp2;
                s1[8 + j] = temp3;
                s1[12 + j] = temp4;
            }

            for (int j = 0; j < 16; j++) s[j] = s1[j];
        }

        int[] ciphertext = new int[s1.length];
        for (int i = 0; i < s1.length; i++) {
            ciphertext[i] = (int) s1[i];
        }

        return s1;
    }

    public static int[] cryptoHash(int[] M) {
        final int M_LENGTH = 32;
        int[] L = new int[16];
        int[] R = new int[16];

        int[] M_pad = Arrays.copyOf(M, M_LENGTH * ((M.length + M_LENGTH - 1) / M_LENGTH));
        M_pad[M_pad.length - 1] = M.length % M_LENGTH;

        for (int i = 0; i < M_pad.length; i += M_LENGTH) {
            if (i == M_pad.length - M_LENGTH) {
                L[0] = L[0] ^ 0x02;
            }

            int[] L_new = skinny_enc(Arrays.copyOf(L, L.length), concatenateArrays(R, Arrays.copyOfRange(M_pad, i, i + M_LENGTH)));
            for (int j = 0; j < L.length; j++) {
                L_new[j] = L_new[j] ^ L[j];
            }

            L[0] = L[0] ^ 0x01;

            int[] R_new = skinny_enc(Arrays.copyOf(L, L.length), concatenateArrays(R, Arrays.copyOfRange(M_pad, i, i + M_LENGTH)));
            for (int j = 0; j < R.length; j++) {
                R_new[j] = R_new[j] ^ L[j];
            }

            L = Arrays.copyOf(L_new, L_new.length);
            R = Arrays.copyOf(R_new, R_new.length);
        }

        return concatenateArrays(L, R);
    }

    public static int[] crypto_aead_encrypt(int[] M, int[] A, int[] N, int[] K) {
        int[] S = new int[16];
        List<Integer> C = new ArrayList<>();
        int m = 0;

        int[] counter = new int[COUNTER_LENGTH];
        counter[0] = 1;

        if (M.length != 0) {
            List<Integer> M1 = new ArrayList<>();
            for (int i = 0; i < M.length; i++) M1.add(M[i]);
            List<List<Integer>> M_parsed = parse(M1, 16);
            m = M_parsed.size() - 1;
            S = skinny_enc(N, tk_encoding(new int[COUNTER_LENGTH], 2, new int[16], K));
            for (int i = 1; i < m; i++) {
                int[] X = skinny_enc(N, tk_encoding(counter, 0, new int[16], S));
                for (int u = 0; u < 16; u++) {
                    C.add(X[u] ^ M[16 * (i - 1) + u]);
                }
                S = skinny_enc(N, tk_encoding(counter, 1, new int[16], S));
                increase_counter(counter);
            }

            int[] X = skinny_enc(N, tk_encoding(counter, 0, new int[16], S));
            for (int u = 0; u < M_parsed.get(m).size(); u++) {
                C.add(X[u] ^ M_parsed.get(m).get(u));
            }
            increase_counter(counter);
        }

        int[] C1 = listToArray(C);

        int[] H = cryptoHash(concat(ipad_star(A, 16), ipad_star(C1, 16), N, counter));
        int[] T = skinny_enc(Arrays.copyOfRange(H, 0, 16), tk_encoding(new int[COUNTER_LENGTH], 4, Arrays.copyOfRange(H, 16, 32), K));
        for (int t : T) {
            C.add(t);
        }

        return listToArray(C);
    }

    public static int[] crypto_aead_decrypt(int[] C, int[] A, int[] N, int[] K) {

        int[] S = new int[16];
        int[] T = Arrays.copyOfRange(C, C.length - 16, C.length);
        int[] C1 = Arrays.copyOf(C, C.length-16);
        List<Integer> M = new ArrayList<>();

        int c = (C1.length + 15 - ((C1.length + 15) % 16)) / 16;
        int[] counter = new int[COUNTER_LENGTH];
        counter[0] = 1;
        for (int i = 0; i < c; i++) {
            increase_counter(counter);
        }

        int[] H = cryptoHash(concat(ipad_star(A, 16), ipad_star(C1, 16), N, counter));
        int[] T_computed = skinny_enc(Arrays.copyOfRange(H, 0, 16), tk_encoding(new int[COUNTER_LENGTH], 4, Arrays.copyOfRange(H, 16, 32), K));
        int compare = 0;
        for (int i = 0; i < 16; i++) {
            compare |= T[i] ^ T_computed[i];
        }

        if (compare != 0) {
            return new int[0];
        } else {
            if (C1.length == 0) {
                return listToArray(M);
            }

            S = skinny_enc(N, tk_encoding(new int[COUNTER_LENGTH], 2, new int[16], K));
            counter = new int[COUNTER_LENGTH];
            counter[0] = 1;
            for (int i = 1; i < c; i++) {
                int[] X = skinny_enc(N, tk_encoding(counter, 0, new int[16], S));
                for (int u = 0; u < 16; u++) {
                    M.add(X[u] ^ C1[16 * (i - 1) + u]);
                }
                S = skinny_enc(N, tk_encoding(counter, 1, new int[16], S));
                increase_counter(counter);
            }

            int[] X = skinny_enc(N, tk_encoding(counter, 0, new int[16], S));
            for (int u = 0; u < 1 + ((C1.length + 15) % 16); u++) {
                M.add(X[u] ^ C1[16 * (c - 1) + u]);
            }
        }

        return listToArray(M);
    }


    public static void main(String[] args) {
        int[] msgf = new int[] {11,1};
        int[] adf = new int[] {};
        int[] noncef = new int[] {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        int[] keyf = new int[] {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

        int[] encryted = crypto_aead_encrypt(msgf, adf, noncef, keyf);
        System.out.print("Encypted text is: ");
        for(int b: encryted) {
            System.out.print(Integer.toHexString(b));
        }
        System.out.println();
        int[] decrypted = crypto_aead_decrypt(encryted, adf, noncef, keyf);
        System.out.print("Decrypted text is: ");
        for(int b: decrypted) {
            System.out.print(Integer.toHexString(b));
        }
        System.out.println();
    }
}