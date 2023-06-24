import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class TestVectorGift {
    private static final int KAT_SUCCESS = 0;
    private static final int KAT_FILE_OPEN_ERROR = -1;
    private static final int KAT_DATA_ERROR = -3;
    private static final int KAT_CRYPTO_FAILURE = -4;

    private static final int MAX_FILE_NAME = 256;
    private static final int MAX_MESSAGE_LENGTH = 32;
    private static final int MAX_ASSOCIATED_DATA_LENGTH = 32;

    private static final int CRYPTO_KEYBYTES = 16;
    private static final int CRYPTO_NSECBYTES = 0;
    private static final int CRYPTO_NPUBBYTES = 16;
    private static final int CRYPTO_ABYTES = 16;
    private static final boolean CRYPTO_NOOVERLAP = true;

    public static int generateTestVectors() throws IOException {
        FileWriter fp;
        String fileName;
        int[] key = new int[CRYPTO_KEYBYTES];
        int[] nonce = new int[CRYPTO_NPUBBYTES];
        int[] msg = new int[MAX_MESSAGE_LENGTH];
        int[] msg2 = new int[MAX_MESSAGE_LENGTH];
        int[] ad = new int[MAX_ASSOCIATED_DATA_LENGTH];

        long clen;
        long mlen2;
        int count = 1;
        int func_ret;
        int ret_val = KAT_SUCCESS;

        initBuffer(key, key.length);
        initBuffer(nonce, nonce.length);
        initBuffer(msg, msg.length);
        initBuffer(ad, ad.length);

        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader("LWC_AEAD_KAT_128_128-GIFT-AUTHOR.txt"));
        } catch (IOException e) {
            System.err.println("Couldn't open LWC_AEAD_KAT_128_128-GIFT-AUTHOR for write");
            return KAT_FILE_OPEN_ERROR;
        }

        for (int mlen = 0; (mlen <= MAX_MESSAGE_LENGTH) && (ret_val == KAT_SUCCESS); mlen++) {
            for (int adlen = 0; adlen <= MAX_ASSOCIATED_DATA_LENGTH; adlen++) {
                // count
                reader.readLine();
                // key
                reader.readLine();
                // Noonce
                reader.readLine();
                // PT
                String[] _auth_PT = reader.readLine().split(" ");
                String auth_PT;
                if (_auth_PT.length > 2)
                    auth_PT = _auth_PT[2];
                else
                    auth_PT = "";
                // AD
                reader.readLine();
                // CT
                String auth_CT = reader.readLine().split(" ")[2];
                // blank
                reader.readLine();
                // System.out.println(auth_PT + " " + auth_CT);

                int[] ct = new int[mlen + CRYPTO_ABYTES];
                int[] _clen = new int[1];

                if ((func_ret = GIFT128.crypto_aead_encrypt(
                         ct, _clen, msg, mlen, ad, adlen, null, nonce, key))
                    != 0) {
                    ret_val = KAT_CRYPTO_FAILURE;
                    break;
                }

                // Compare with author's CT
                String myCTHex = toHex(ct, _clen[0]);
                if (!auth_CT.equals(myCTHex)) {
                    System.out.println(
                        "Author's CT and our CT is not equal: " + auth_CT + " " + myCTHex);
                }

                int[] _mlen2 = new int[msg.length];
                _mlen2[0] = msg.length;
                if ((func_ret = GIFT128.crypto_aead_decrypt(
                         msg2, _mlen2, null, ct, _clen[0], ad, adlen, nonce, key))
                    != 0) {
                    ret_val = KAT_CRYPTO_FAILURE;
                    break;
                }

                if (mlen != _mlen2[0]) {
                    ret_val = KAT_CRYPTO_FAILURE;
                    break;
                }

                if (!ArrayEqual(msg, msg2, mlen)) {
                    ret_val = KAT_CRYPTO_FAILURE;
                    break;
                }

                // Compare with author's PT
                String myPTHex = toHex(msg2, mlen);
                if (!auth_PT.equals(myPTHex)) {
                    System.out.println(
                        "Author's CT and our CT is not equal: " + auth_PT + " " + myPTHex);
                }
            }
        }

        reader.close();
        return ret_val;
    }

    static String toHex(int[] data, long length) {
        String r = "";
        for (long i = 0; i < length; i++) {
            r += String.format("%02X", data[(int) i]);
        }
        return r;
    }

    public static void initBuffer(int[] buffer, long numbytes) {
        for (long i = 0; i < numbytes; i++) {
            buffer[(int) i] = (int) i;
        }
    }

    public static boolean ArrayEqual(int[] m, int[] m2, long l) {
        if (l == 0) {
            return true;
        }
        for (int i = 0; i < (int) l; i++) {
            if (m[i] != m2[i]) {
                return false;
            }
        }
        return true;
    }

    public static void main(String[] args) throws IOException {
        generateTestVectors();
    }
}