//package org.example;

import java.io.FileWriter;
import java.io.IOException;

public class TestVectorsTinyJambu {
    private static final int MAX_MESSAGE_LENGTH = 32;
    private static final int MAX_ASSOCIATED_DATA_LENGTH = 32;

    private static final int CRYPTO_KEYBYTES = 16;
    private static final int CRYPTO_NPUBBYTES = 16;

    // Write the file name
    private static String file_name = "TINYJAMBU-TEST-VEC.txt";

    static final String digits = "0123456789ABCDEF";
    static String integerToHex(long i) {
        int input = (int) i;
        if (input <= 0)
            return "00";
        StringBuilder hex = new StringBuilder();
        while (input > 0) {
            int digit = (int) input % 16;
            hex.insert(0, digits.charAt(digit));
            input = input / 16;
        }
        if(hex.length() == 1) {
            hex.append("0");
            hex.reverse();
        }
        return hex.toString();
    }

    public static String convertToHexString(long[] input) {
        String temp = "";
        for (int i = 0; i < input.length; i++) {
            temp += integerToHex(input[i]);
        }
        return temp;
    }

    public static String convertToHexString(long[] input, int limit) {
        String temp = "";
        for (int i = 0; i < limit; i++) {
            temp += integerToHex(input[i]);
        }
        return temp;
    }

    public static boolean equals(long[] m, long[] d) {
        for (int i = 0; i < m.length; i++) {
            if (m[i] != d[i]) return false;
        }
        return true;
    }

    public static void main(String args[]) {
        try {

            FileWriter myWriter = new FileWriter(file_name);

            int count = 0;
            long[] T = new long[64];
            long[] S = new long[128];
            for (int mlen = 0; mlen <= MAX_MESSAGE_LENGTH; mlen++) {
                for (int adlen = 0; adlen <= MAX_ASSOCIATED_DATA_LENGTH; adlen++) {

                    count += 1;
                    
                    long[] key = new long[CRYPTO_KEYBYTES];
                    long[] nonce = new long[96];
                    long[] msg = new long[mlen];
                    long[] ad = new long[adlen];
                    

                    for (int i = 0; i < CRYPTO_KEYBYTES; i++) {
                        key[i] = i % 256;
                    }
                    for (int i = 0; i < CRYPTO_NPUBBYTES; i++) {
                        nonce[i] = i % 256;
                    }
                    for (int i = 0; i < mlen; i++) {
                        msg[i] = i % 256;
                    }
                    for (int i = 0; i < adlen; i++) {
                        ad[i] = i % 256;
                    }

                    String original_message = convertToHexString(msg);
                    System.out.println("Original Message = " + original_message);

                    myWriter.write("Count = " + count + "\n");
                    myWriter.write("Key = " + convertToHexString(key) + "\n");
                    myWriter.write("Nonce = " + convertToHexString(nonce) + "\n");
                    myWriter.write("PT = " + convertToHexString(msg) + "\n");
                    myWriter.write("AD = " + convertToHexString(ad) + "\n");
                    long[] ct = new long[mlen+100];
                    jambu2.tinyjambuEncrypt(S, key, nonce, T, msg, ct, ad);

                    myWriter.write("CT = " + convertToHexString(ct) + "\n");
                    
                    long[] dct = new long[mlen + 100];
                    jambu2.tinyjambuDecrypt(S, key, nonce, T, dct, ct, ad);
                    String decrypted_text = convertToHexString(dct, msg.length);

                    System.out.println("Decrypted Message = " + decrypted_text);
                    
                    if (!decrypted_text.equals(original_message)) {
                        myWriter.write("Error: crypto_aead_decrypt did not recover the plaintext \n");
                        return;
                    } 
                    myWriter.write("\n"); 
                }
            }
            
            
            int mlen = 243;
            int adlen = 147;
            count += 1;

             long[] key = new long[CRYPTO_KEYBYTES];
             long[] nonce = new long[96];
             long[] msg = new long[mlen];
             long[] ad = new long[adlen];

            for (int i = 0; i < CRYPTO_KEYBYTES; i++) {
                key[i] = i % 256;
            }
            for (int i = 0; i < CRYPTO_NPUBBYTES; i++) {
                nonce[i] = i % 256;
            }
            for (int i = 0; i < mlen; i++) {
                msg[i] = i % 256;
            }
            for (int i = 0; i < adlen; i++) {
                ad[i] = i % 256;
            }

            String original_message = convertToHexString(msg);
            System.out.println("Original Message = " + original_message);

            myWriter.write("Count = " + count + "\n");
            myWriter.write("Key = " + convertToHexString(key) + "\n");
            myWriter.write("Nonce = " + convertToHexString(nonce) + "\n");
            myWriter.write("PT = " + convertToHexString(msg) + "\n");
            myWriter.write("AD = " + convertToHexString(ad) + "\n");

            long[] ct = new long[mlen+100];
            jambu2.tinyjambuEncrypt(S, key, nonce, T, msg, ct, ad);

            myWriter.write("CT = " + convertToHexString(ct) + "\n");


            long[] dct = new long[mlen + 100];
            jambu2.tinyjambuDecrypt(S, key, nonce, T, dct, ct, ad);

            String decrypted_text = convertToHexString(dct, msg.length);

            System.out.println("Decrypted Message = " + decrypted_text);

            if (!(decrypted_text.equals(original_message))) {
                myWriter.write("Error: crypto_aead_decrypt did not recover the plaintext \n");
                return;
            }
            
            myWriter.write("\n");
            
            myWriter.close();
            System.out.println("Successfully wrote to the file " + file_name + "."); 

        } catch (IOException e) {

            System.out.println("An error occurred.");
            e.printStackTrace();

        }
    }
}
