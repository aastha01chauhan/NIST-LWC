//package org.example;

import java.io.FileWriter;
import java.io.IOException;

public class GrainTestVector {
    private static final int MAX_MESSAGE_LENGTH = 32;
    private static final int MAX_ASSOCIATED_DATA_LENGTH = 32;

    private static final int CRYPTO_KEYBYTES = 16;
    private static final int CRYPTO_NPUBBYTES = 16;

    // Write the file name
    private static String file_name = "GRAIN-TEST-VEC.txt";

    static final String digits = "0123456789ABCDEF";
    static String integerToHex(int i) {
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

    public static String convertToHexString(int[] input) {
        String temp = "";
        for (int i = 0; i < input.length; i++) {
            temp += integerToHex(input[i]);
        }
        return temp;
    }

    public static String convertToHexString(int[] input, int limit) {
        String temp = "";
        for (int i = 0; i < limit; i++) {
            temp += integerToHex(input[i]);
        }
        return temp;
    }

   

    public static void main(String args[]) {
        try {

            FileWriter myWriter = new FileWriter(file_name);

            int count = 0;

            for (int mlen = 0; mlen <= MAX_MESSAGE_LENGTH; mlen++) {
                for (int adlen = 0; adlen <= MAX_ASSOCIATED_DATA_LENGTH; adlen++) {

                    count += 1;
                    
                    int[] key = new int[CRYPTO_KEYBYTES];
                    int[] nonce = new int[CRYPTO_NPUBBYTES];
                    int[] msg = new int[mlen];
                    int[] ks = new int[mlen];
                    

                    for (int i = 0; i < CRYPTO_KEYBYTES; i++) {
                        key[i] = i % 256;
                    }
                    for (int i = 0; i < CRYPTO_NPUBBYTES; i++) {
                        nonce[i] = i % 256;
                    }
                    for (int i = 0; i < mlen; i++) {
                        msg[i] = i % 256;
                    }
                   

                    String original_message = convertToHexString(msg);
                    System.out.println("Original Message = " + original_message);

                    myWriter.write("Count = " + count + "\n");
                    myWriter.write("Key = " + convertToHexString(key) + "\n");
                    myWriter.write("Nonce = " + convertToHexString(nonce) + "\n");
                    myWriter.write("PT = " + convertToHexString(msg) + "\n");

                    int[] ct = new int[mlen];
                    GrainObject mygrain = new GrainObject();
                    GrainObject mygrain_d = new GrainObject();
                    Grain.keysetup(mygrain, key, key.length, nonce.length); 
                    Grain.ivsetup(mygrain, nonce);
                    Grain.keystream_bytes(mygrain, ks, msg.length);
                    mygrain.Copy(mygrain_d);
                    Grain.encrypt_bytes(mygrain, msg, ct, msg.length);
                    
                    myWriter.write("CT = " + convertToHexString(ct) + "\n");

                    
                    int[] dct = new int[mlen];
                    Grain.decrypt_bytes(mygrain_d, ct, dct, msg.length);
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
            int[] ks = new int[mlen];
             int[] key = new int[CRYPTO_KEYBYTES];
             int[] nonce = new int[CRYPTO_NPUBBYTES];
             int[] msg = new int[mlen];
             int[] ad = new int[adlen];

            for (int i = 0; i < CRYPTO_KEYBYTES; i++) {
                key[i] = i % 256;
            }
            for (int i = 0; i < CRYPTO_NPUBBYTES; i++) {
                nonce[i] = i % 256;
            }
            for (int i = 0; i < mlen; i++) {
                msg[i] = i % 256;
            }

            String original_message = convertToHexString(msg);
            System.out.println("Original Message = " + original_message);

            myWriter.write("Count = " + count + "\n");
            myWriter.write("Key = " + convertToHexString(key) + "\n");
            myWriter.write("Nonce = " + convertToHexString(nonce) + "\n");
            myWriter.write("PT = " + convertToHexString(msg) + "\n");

            int[] ct = new int[mlen];
            GrainObject mygrain = new GrainObject();
            GrainObject mygrain_d = new GrainObject();
            Grain.keysetup(mygrain, key, key.length, nonce.length); 
            Grain.ivsetup(mygrain, nonce);
            Grain.keystream_bytes(mygrain, ks, msg.length);
            mygrain.Copy(mygrain_d);
            Grain.encrypt_bytes(mygrain, msg, ct, msg.length);
                    
            myWriter.write("CT = " + convertToHexString(ct) + "\n");

                    
            int[] dct = new int[mlen];
            Grain.decrypt_bytes(mygrain_d, ct, dct, msg.length);

            String decrypted_text = convertToHexString(dct);

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