import java.util.Arrays;

public class PhotonBeetle128AEAD {
    private static final int CRYPTO_KEYBYTES = 16;
    private static final int CRYPTO_NSECBYTES = 0;
    private static final int CRYPTO_NPUBBYTES = 16;
    private static final int CRYPTO_ABYTES = 16;
    private static final int CRYPTO_NOOVERLAP = 1;

    private static final int RATE_INBITS = 128;
    private static final int RATE_INBYTES = (RATE_INBITS + 7) / 8;

    private static final int SQUEEZE_RATE_INBITS = 128;
    private static final int SQUEEZE_RATE_INBYTES = (SQUEEZE_RATE_INBITS + 7) / 8;

    private static final int CAPACITY_INBITS = 128;
    private static final int CAPACITY_INBYTES = (CAPACITY_INBITS + 7) / 8;

    private static final int STATE_INBITS = RATE_INBITS + CAPACITY_INBITS;
    private static final int STATE_INBYTES = (STATE_INBITS + 7) / 8;

    private static final int KEY_INBITS = CRYPTO_KEYBYTES * 8;
    private static final int KEY_INBYTES = CRYPTO_KEYBYTES;

    private static final int NOUNCE_INBITS = CRYPTO_NPUBBYTES * 8;
    private static final int NOUNCE_INBYTES = CRYPTO_NPUBBYTES;

    private static final int TAG_INBITS = 128;
    private static final int TAG_INBYTES = (TAG_INBITS + 7) / 8;

    private static final int LAST_THREE_BITS_OFFSET = STATE_INBITS - (STATE_INBYTES - 1) * 8 - 3;

    private static final int TAG_MATCH = 0;
    private static final int TAG_UNMATCH = -1;
    private static final int OTHER_FAILURES = -2;

    private static final int ENC = 0;
    private static final int DEC = 1;

    private static final int ROUND = 12;
    private static final int D = 8;
    private static final int S = 4;
    private static final int ReductionPoly = 0x3;
    private static final int WORDFILTER = ((int) 1 << S) - 1;
    private static int DEBUG = 0;
    private static long MessBitLen = 0;

    private static final int[][] RC = {{1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10},
        {0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11}, {2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9},
        {6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13}, {14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5},
        {15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4}, {13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6},
        {9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2}};

    private static final int[][] MixColMatrix = {{2, 4, 2, 11, 2, 8, 5, 6},
        {12, 9, 8, 13, 7, 7, 5, 2}, {4, 4, 13, 13, 9, 4, 13, 9}, {1, 6, 5, 1, 12, 13, 15, 14},
        {15, 12, 9, 13, 14, 5, 14, 13}, {9, 14, 5, 15, 4, 12, 9, 6}, {12, 2, 2, 10, 3, 1, 1, 14},
        {15, 1, 13, 10, 5, 10, 2, 3}};

    private static final int[] sbox = {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};

    public static int min(int x, int y) {
        return (x < y) ? x : y;
    }

    public static int max(int x, int y) {
        return (x > y) ? x : y;
    }

    public static int FieldMult(int a, int b) {
        int x = a;
        int ret = 0;

        for (int i = 0; i < S; i++) {
            if (((b >>> i) & 1) != 0)
                ret ^= x;

            if (((x >>> (S - 1)) & 1) != 0) {
                x <<= 1;
                x ^= ReductionPoly;
            } else {
                x <<= 1;
            }
        }

        return ret & WORDFILTER;
    }

    public static void AddKey(int[][] state, int round) {
        for (int i = 0; i < D; i++) {
            state[i][0] ^= RC[i][round];
        }
    }

    public static void SubCell(int[][] state) {
        for (int i = 0; i < D; i++) {
            for (int j = 0; j < D; j++) {
                state[i][j] = sbox[state[i][j]];
            }
        }
    }

    public static void ShiftRow(int[][] state) {
        int[] tmp = new int[D];
        for (int i = 1; i < D; i++) {
            for (int j = 0; j < D; j++) {
                tmp[j] = state[i][j];
            }
            for (int j = 0; j < D; j++) {
                state[i][j] = tmp[(j + i) % D];
            }
        }
    }

    public static void MixColumn(int[][] state) {
        int[] tmp = new int[D];
        for (int j = 0; j < D; j++) {
            for (int i = 0; i < D; i++) {
                int sum = 0;

                for (int k = 0; k < D; k++) {
                    sum ^= FieldMult(MixColMatrix[i][k], state[k][j]);
                }

                tmp[i] = sum;
            }

            for (int i = 0; i < D; i++) {
                state[i][j] = tmp[i];
            }
        }
    }

    public static void Permutation(int[][] state, int R) {
        for (int i = 0; i < R; i++) {
            if (DEBUG != 0) {
                System.out.println("--- Round " + i + " ---");
            }

            AddKey(state, i);
            PrintState(state);

            SubCell(state);
            PrintState(state);

            ShiftRow(state);
            PrintState(state);

            MixColumn(state);
            PrintState(state);
        }
    }

    public static void PHOTON_Permutation(int[] State_in) {
        int[][] state = new int[D][D];

        for (int i = 0; i < D * D; i++) {
            state[i / D][i % D] = (State_in[i / 2] >> (4 * (i & 1))) & 0xF;
        }

        Permutation(state, ROUND);

        Arrays.fill(State_in, 0, (D * D) / 2, 0);
        for (int i = 0; i < D * D; i++) {
            State_in[i / 2] |= (state[i / D][i % D] & 0xF) << (4 * (i & 1));
        }
    }

    public static void PrintState(int[][] state) {
        if (DEBUG == 0)
            return;

        for (int i = 0; i < D; i++) {
            for (int j = 0; j < D; j++) {
                System.out.print(String.format("%2X ", state[i][j]));
            }
            System.out.println();
        }
        System.out.println();
    }

    public static int selectConst(boolean condition1, boolean condition2, int option1, int option2,
        int option3, int option4) {
        if (condition1 && condition2)
            return option1;
        if (condition1)
            return option2;
        if (condition2)
            return option3;
        return option4;
    }

    public static void concatenate(
        int[] out, int[] in_left, int leftlen_inbytes, int[] in_right, int rightlen_inbytes) {
        System.arraycopy(in_left, 0, out, 0, leftlen_inbytes);
        System.arraycopy(in_right, 0, out, leftlen_inbytes, rightlen_inbytes);
    }

    public static void XOR(
        int[] out, int[] in_left, int[] in_right, int right_index, int iolen_inbytes) {
        for (int i = 0; i < iolen_inbytes; i++) {
            out[i] = in_left[i] ^ in_right[i + right_index];
        }
    }

    public static void XOR_const(int[] State_inout, int Constant) {
        State_inout[STATE_INBYTES - 1] ^= (Constant << LAST_THREE_BITS_OFFSET);
    }

    public static void ROTR1(int[] out, int[] in, int iolen_inbytes) {
        int tmp = in[0];
        for (int i = 0; i < iolen_inbytes - 1; i++) {
            out[i] = (in[i] >>> 1) | ((in[i + 1] & 1) << 7);
        }
        out[iolen_inbytes - 1] = (in[iolen_inbytes - 1] >>> 1) | ((tmp & 1) << 7);
    }

    public static void ShuffleXOR(int[] DataBlock_out, int dout_index, int[] OuterState_in,
        int[] DataBlock_in, int din_index, int DBlen_inbytes) {
        int[] OuterState_part1_ROTR1 = new int[RATE_INBYTES / 2];
        ROTR1(OuterState_part1_ROTR1, OuterState_in, RATE_INBYTES / 2);

        int i = 0;
        while ((i < DBlen_inbytes) && (i < RATE_INBYTES / 2)) {
            DataBlock_out[i + dout_index] =
                OuterState_in[i + (RATE_INBYTES / 2)] ^ DataBlock_in[i + din_index];
            i++;
        }
        while (i < DBlen_inbytes) {
            DataBlock_out[i + dout_index] =
                OuterState_part1_ROTR1[i - RATE_INBYTES / 2] ^ DataBlock_in[i + din_index];
            i++;
        }
    }

    public static void rhoohr(int[] OuterState_inout, int[] DataBlock_out, int dout_index,
        int[] DataBlock_in, int din_index, int DBlen_inbytes, int EncDecInd) {
        ShuffleXOR(
            DataBlock_out, dout_index, OuterState_inout, DataBlock_in, din_index, DBlen_inbytes);

        if (EncDecInd == ENC) {
            XOR(OuterState_inout, OuterState_inout, DataBlock_in, din_index, DBlen_inbytes);
        } else {
            XOR(OuterState_inout, OuterState_inout, DataBlock_out, dout_index, DBlen_inbytes);
        }
    }

    public static void HASH(int[] State, int[] Data_in, long Dlen_inbytes, int Constant) {
        // int[] State = State_inout;
        long Dlen_inblocks = (Dlen_inbytes + RATE_INBYTES - 1) / RATE_INBYTES;
        long LastDBlocklen;
        int i;

        for (i = 0; i < Dlen_inblocks - 1; i++) {
            PHOTON_Permutation(State);
            XOR(State, State, Data_in, i * RATE_INBYTES, RATE_INBYTES);
        }
        PHOTON_Permutation(State);
        LastDBlocklen = Dlen_inbytes - i * RATE_INBYTES;
        XOR(State, State, Data_in, i * RATE_INBYTES, (int) LastDBlocklen);
        if (LastDBlocklen < RATE_INBYTES)
            State[(int) LastDBlocklen] ^= 0x01; // ozs

        XOR_const(State, Constant);
    }

    public static void ENCorDEC(int[] State_inout, int[] Data_out, int[] Data_in, long Dlen_inbytes,
        int Constant, int EncDecInd) {
        int[] State = State_inout;
        long Dlen_inblocks = (Dlen_inbytes + RATE_INBYTES - 1) / RATE_INBYTES;
        long LastDBlocklen;
        int i;

        for (i = 0; i < Dlen_inblocks - 1; i++) {
            PHOTON_Permutation(State);
            rhoohr(State, Data_out, i * RATE_INBYTES, Data_in, i * RATE_INBYTES, RATE_INBYTES,
                EncDecInd);
        }
        PHOTON_Permutation(State);
        LastDBlocklen = Dlen_inbytes - i * RATE_INBYTES;
        rhoohr(State, Data_out, i * RATE_INBYTES, Data_in, i * RATE_INBYTES, (int) LastDBlocklen,
            EncDecInd);
        if (LastDBlocklen < RATE_INBYTES)
            State[(int) LastDBlocklen] ^= 0x01; // ozs

        XOR_const(State, Constant);
    }

    public static void TAG(int[] Tag_out, int[] State) {
        int i = TAG_INBYTES;
        int TagIndex = 0;

        while (i > SQUEEZE_RATE_INBYTES) {
            PHOTON_Permutation(State);
            System.arraycopy(State, 0, Tag_out, TagIndex, SQUEEZE_RATE_INBYTES);
            TagIndex += SQUEEZE_RATE_INBYTES;
            i -= SQUEEZE_RATE_INBYTES;
        }
        PHOTON_Permutation(State);
        System.arraycopy(State, 0, Tag_out, TagIndex, i);
    }

    public static int crypto_aead_encrypt(int[] c, long[] clen, int[] m, long mlen, int[] ad,
        long adlen, int[] nsec, int[] npub, int[] k) {
        int[] C = c;
        int[] T = new int[16];
        int[] M = m;
        int[] A = ad;
        int[] N = npub;
        int[] K = k;

        int[] State = new int[STATE_INBYTES];
        int c0;
        int c1;

        // Ignore nsec

        concatenate(State, N, NOUNCE_INBYTES, K, KEY_INBYTES);

        if ((adlen == 0) && (mlen == 0)) {
            XOR_const(State, 1);
            TAG(T, State);
            clen[0] = TAG_INBYTES;
            for (int i = 0; i < T.length; i++) c[i + (int) mlen] = T[i];
            return 0;
        }

        c0 = selectConst((mlen != 0), ((adlen % RATE_INBYTES) == 0), 1, 2, 3, 4);
        c1 = selectConst((adlen != 0), ((mlen % RATE_INBYTES) == 0), 1, 2, 5, 6);

        if (adlen != 0)
            HASH(State, A, adlen, c0);
        if (mlen != 0)
            ENCorDEC(State, C, M, mlen, c1, ENC);

        TAG(T, State);
        for (int i = 0; i < T.length; i++) c[i + (int) mlen] = T[i];
        // System.out.println(Arrays.toString(T));
        clen[0] = mlen + TAG_INBYTES;
        return 0;
    }

    public static int crypto_aead_decrypt(int[] m, long[] mlen, final int[] nsec, final int[] c,
        long clen, final int[] ad, long adlen, final int[] npub, final int[] k) {
        int[] M = m;
        int[] C = c;
        int[] T = new int[16];
        int[] A = ad;
        int[] N = npub;
        int[] K = k;

        int[] State = new int[STATE_INBYTES];
        int[] T_tmp = new int[TAG_INBYTES];
        int c0;
        int c1;
        long cmtlen;

        // Ignore nsec

        if (clen < TAG_INBYTES)
            return TAG_UNMATCH;
        cmtlen = clen - TAG_INBYTES;

        concatenate(State, N, NOUNCE_INBYTES, K, KEY_INBYTES);

        if ((adlen == 0) && (cmtlen == 0)) {
            XOR_const(State, 1);
            TAG(T_tmp, State);
            if (!Arrays.equals(T_tmp, T))
                return TAG_UNMATCH;
            mlen[0] = 0;
            return TAG_MATCH;
        }

        c0 = selectConst((cmtlen != 0), ((adlen % RATE_INBYTES) == 0), 1, 2, 3, 4);
        c1 = selectConst((adlen != 0), ((cmtlen % RATE_INBYTES) == 0), 1, 2, 5, 6);

        if (adlen != 0)
            HASH(State, A, adlen, c0);
        if (cmtlen != 0) {
            ENCorDEC(State, M, C, cmtlen, c1, DEC);
        }

        TAG(T_tmp, State);
        if (!Arrays.equals(T_tmp, T)) {
            return TAG_UNMATCH;
        }

        if (cmtlen != 0) {
            System.arraycopy(M, 0, m, 0, (int) cmtlen);
        }
        mlen[0] = cmtlen;
        return TAG_MATCH;
    }

    public static void main(String[] args) {
        int[] m = new int[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        System.out.println("Original: " + Arrays.toString(m));
        long mlen = m.length;
        int[] c = new int[(int) mlen + 16];
        long[] clen = new long[1];
        int[] ad = new int[] {10, 20, 30};
        long adlen = ad.length;
        int[] npub = new int[16];
        for (int i = 0; i < 16; i++) npub[i] = i;
        int[] k = new int[16];
        for (int i = 0; i < 16; i++) k[i] = i;
        crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, null, npub, k);
        System.out.println("Ecnrypted: " + Arrays.toString(c));

        int[] dec = new int[m.length];
        long[] dec_len = new long[1];
        crypto_aead_decrypt(dec, dec_len, null, c, clen[0], ad, adlen, npub, k);
        System.out.println("Decrypted: " + Arrays.toString(dec));
    }
}