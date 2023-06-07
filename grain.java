

class GrainObject {
    public int[] LFSR;
    public int[] NFSR;
    public int[] p_key;
    public int keysize;
    public int ivsize;

    public GrainObject() {
        this.LFSR = new int[80];
        this.NFSR = new int[80];
        this.p_key = new int[80];
    }

    public void Copy(GrainObject other) {
        for (int i = 0; i < this.LFSR.length; i++) other.LFSR[i] = this.LFSR[i];
        for (int i = 0; i < this.NFSR.length; i++) other.NFSR[i] = this.NFSR[i];
        for (int i = 0; i < this.p_key.length; i++) other.p_key[i] = this.p_key[i];
        other.keysize = this.keysize;
        other.ivsize = this.ivsize;
    }

    public static final int INITCLOCKS = 160;

    public int N(int i) {
        return NFSR[80 - i];
    }

    public int L(int i) {
        return LFSR[80 - i];
    }

    public int X0() {
        return LFSR[3];
    }

    public int X1() {
        return LFSR[25];
    }

    public int X2() {
        return LFSR[46];
    }

    public int X3() {
        return LFSR[64];
    }

    public int X4() {
        return NFSR[63];
    }
}

class Grain {
    public static int grain_keystream(GrainObject mygrain) {
        int i, NBit, LBit, outbit;
        /* Calculate feedback and output bits */
        outbit = mygrain.N(79) ^ mygrain.N(78) ^ mygrain.N(76) ^ mygrain.N(70) ^ mygrain.N(49)
            ^ mygrain.N(37) ^ mygrain.N(24) ^ mygrain.X1() ^ mygrain.X4()
            ^ (mygrain.X0() & mygrain.X3()) ^ (mygrain.X2() & mygrain.X3())
            ^ (mygrain.X3() & mygrain.X4()) ^ (mygrain.X0() & mygrain.X1() & mygrain.X2())
            ^ (mygrain.X0() & mygrain.X2() & mygrain.X3())
            ^ (mygrain.X0() & mygrain.X2() & mygrain.X4())
            ^ (mygrain.X1() & mygrain.X2() & mygrain.X4())
            ^ (mygrain.X2() & mygrain.X3() & mygrain.X4());

        NBit = mygrain.L(80) ^ mygrain.N(18) ^ mygrain.N(20) ^ mygrain.N(28) ^ mygrain.N(35)
            ^ mygrain.N(43) ^ mygrain.N(47) ^ mygrain.N(52) ^ mygrain.N(59) ^ mygrain.N(66)
            ^ mygrain.N(71) ^ mygrain.N(80) ^ (mygrain.N(17) & mygrain.N(20))
            ^ (mygrain.N(43) & mygrain.N(47)) ^ (mygrain.N(65) & mygrain.N(71))
            ^ (mygrain.N(20) & mygrain.N(28) & mygrain.N(35))
            ^ (mygrain.N(47) & mygrain.N(52) & mygrain.N(59))
            ^ (mygrain.N(17) & mygrain.N(35) & mygrain.N(52) & mygrain.N(71))
            ^ (mygrain.N(20) & mygrain.N(28) & mygrain.N(43) & mygrain.N(47))
            ^ (mygrain.N(17) & mygrain.N(20) & mygrain.N(59) & mygrain.N(65))
            ^ (mygrain.N(17) & mygrain.N(20) & mygrain.N(28) & mygrain.N(35) & mygrain.N(43))
            ^ (mygrain.N(47) & mygrain.N(52) & mygrain.N(59) & mygrain.N(65) & mygrain.N(71))
            ^ (mygrain.N(28) & mygrain.N(35) & mygrain.N(43) & mygrain.N(47) & mygrain.N(52)
                & mygrain.N(59));

        LBit = mygrain.L(18) ^ mygrain.L(29) ^ mygrain.L(42) ^ mygrain.L(57) ^ mygrain.L(67)
            ^ mygrain.L(80);

        /* Update registers */
        for (i = 1; i < mygrain.keysize; ++i) {
            mygrain.NFSR[i - 1] = mygrain.NFSR[i];
            mygrain.LFSR[i - 1] = mygrain.LFSR[i];
        }
        mygrain.NFSR[mygrain.keysize - 1] = NBit;
        mygrain.LFSR[mygrain.keysize - 1] = LBit;

        return outbit;
    }

    public static void keysetup(GrainObject mygrain, int[] key, int keysize, int ivsize) {
        mygrain.p_key = key;
        mygrain.keysize = keysize;
        mygrain.ivsize = ivsize;
    }

    public static void ivsetup(GrainObject mygrain, int[] iv) {
        int i, j;
        int outbit;
        /* load registers */
        for (i = 0; i < mygrain.ivsize / 8; ++i) {
            for (j = 0; j < 8; ++j) {
                mygrain.NFSR[i * 8 + j] = ((mygrain.p_key[i] >> j) & 1);
                mygrain.LFSR[i * 8 + j] = ((iv[i] >> j) & 1);
            }
        }
        for (i = mygrain.ivsize / 8; i < mygrain.keysize / 8; ++i) {
            for (j = 0; j < 8; ++j) {
                mygrain.NFSR[i * 8 + j] = ((mygrain.p_key[i] >> j) & 1);
                mygrain.LFSR[i * 8 + j] = 1;
            }
        }
        /* do initial clockings */
        for (i = 0; i < mygrain.INITCLOCKS; ++i) {
            outbit = grain_keystream(mygrain);
            /* System.out.print(outbit); */
            mygrain.LFSR[79] = mygrain.LFSR[79] ^ outbit;
            mygrain.NFSR[79] = mygrain.NFSR[79] ^ outbit;
        }
    }

    public static void keystream_bytes(GrainObject mygrain, int[] keystream, int msglen) {
        int i, j;
        for (i = 0; i < msglen; ++i) {
            keystream[i] = 0;
            for (j = 0; j < 8; ++j) {
                keystream[i] |= (grain_keystream(mygrain) << j);
            }
        }
    }

    public static void encrypt_bytes(
        GrainObject mygrain, int[] plaintext, int[] ciphertext, int msglen) {
        int i, j;
        int k;
        for (i = 0; i < msglen; ++i) {
            k = 0;
            for (j = 0; j < 8; ++j) {
                k |= (grain_keystream(mygrain) << j);
            }
            ciphertext[i] = plaintext[i] ^ k;
        }
    }

    public static void decrypt_bytes(
        GrainObject mygrain, int[] ciphertext, int[] plaintext, int msglen) {
        int i, j;
        int k;
        for (i = 0; i < msglen; ++i) {
            k = 0;
            for (j = 0; j < 8; ++j) {
                k |= (grain_keystream(mygrain) << j);
            }
            plaintext[i] = ciphertext[i] ^ k;
        }
    }

    public static void main(String[] args) {
        int[] msg = new int[100];
        for (int i = 0; i < 100; i++) {
            if (i % 2 == 0) {
                msg[i] = i + 26;
            } else {
                msg[i] = i ^ 56;
            }
        }

        for (int i = 0; i < msg.length; i++) System.out.print(msg[i] + " ");
        System.out.println();

        int msglen = msg.length;
        int[] decrypted = new int[100];
        int[] encrypted = new int[100];

        GrainObject mygrain = new GrainObject();
        GrainObject mygrain_d = new GrainObject();
        int[] key = new int[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        int[] IV = new int[] {0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        int[] ks = new int[100];

        keysetup(mygrain, key, 80, 64);
        // keysetup(mygrain_d, key, 80, 64);
        // System.out.println(mygrain.ivsize);
        ivsetup(mygrain, IV);
        // ivsetup(mygrain_d, IV);
        keystream_bytes(mygrain, ks, 100);
        // keystream_bytes(mygrain_d, ks, 100);
        mygrain.Copy(mygrain_d);
        //  for(int i = 0; i < 100; i++) System.out.print( String.format("%02X", ks[i]) + " ");
        System.out.println();

        encrypt_bytes(mygrain, msg, encrypted, 100);
        decrypt_bytes(mygrain_d, encrypted, decrypted, 100);
        for (int i = 0; i < encrypted.length; i++)
            System.out.print(String.format("%02X", encrypted[i]) + " ");
        System.out.println();
        System.out.println();
        for (int i = 0; i < msg.length; i++) System.out.print(decrypted[i] + " ");
        System.out.println();
    }
}