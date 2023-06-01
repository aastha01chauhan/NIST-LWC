import java.util.ArrayList;
import java.util.Arrays;

public class jambu2 {
    public static long[] stateUpdate(long[] S, long[] K, int iRound) {
        int klen = K.length;
        ArrayList<Long> SList = new ArrayList<>();
        for (long value : S) {
            SList.add(value);
        }
        for (int i = 0; i < iRound; i++) {
            long feedback = SList.get(0) ^ SList.get(47) ^ (0x1 - (SList.get(70) & SList.get(85))) ^ SList.get(91) ^ (K[iRound % klen]);
            for (int j = 0; j < 127; j++) {
                SList.add(j, SList.remove(j) + 1);
            }
            SList.set(127, feedback);
        }
        long[] updatedS = new long[SList.size()];
        for (int i = 0; i < SList.size(); i++) {
            updatedS[i] = SList.get(i);
        }
        return updatedS;
    }
    
    public static long[] tinyjambuEncrypt(long[] S, long[] K, long[] N, long[] T, long[] M, long[] C, long[] AD) {
        // The initialization
        // Key setup: Randomize state S using keyed permutation P_1024
        
          // FrameBits
        long[] FB_n = {0, 0, 1};
        long[] FB_ad = {0, 1, 1};
        long[] FB_pc = {1, 0, 1};
        long[] FB_f = {1, 1, 1};

        long[] _M;
        int padding = 32 - (M.length % 32);
        //System.out.println(padding);
        if (padding > 0){
            int paddingStart = M.length - padding;
            _M = new long[M.length + padding];
            for (int i = 0; i < M.length; i++) _M[i] = M[i];
            for(int i = M.length; i < M.length + padding; i++) _M[i] = 0;
            M = _M;
            
        } 
        
        
        S = stateUpdate(S, K, 1024);

        // Nonce setup: Consists of three steps.
        // In each step, XOR the frame bits (FB_n) of the nonce with state S,
        // then update the state using keyed permutation P_640,
        // and finally XOR the 32 bits of the nonce with the state.
        for (int i = 0; i < 3; i++) {
            for (int j = 36; j < 39; j++) {
                S[j] ^= FB_n[j - 36];
            }
            S = stateUpdate(S, K, 640);
            for (int j = 0; j < 32; j++) {
                S[j + 96] ^= N[j + 32 * i];
            }
        }

        // Processing the associated data
        // Process complete blocks of associated data:
        // XOR the frame bits (FB_ad) of the associated data with state S,
        // then update the state using keyed permutation P_640,
        // and finally XOR the 32 bits of the associated data with the state.
        int adlen = AD.length;
        if (adlen >= 32) {
            for (int j = 0; j < adlen / 32; j++) {
                for (int k = 36; k < 39; k++) {
                    S[k] ^= FB_ad[k - 36];
                }
                S = stateUpdate(S, K, 640);
                for (int k = 0; k < 32; k++) {
                    S[k + 96] ^= AD[k + 32 * j];
                }
            }
        }

        // Process the remaining partial block of associated data:
        // If the last block is not a complete block (partial block),
        // XOR the last block with state S and XOR the number of bytes of the associated data with state S.
        if (adlen % 32 > 0) {
            for (int k = 36; k < 39; k++) {
                S[k] ^= FB_ad[k - 36];
            }
            S = stateUpdate(S, K, 640);
            int lenp = adlen % 32;
            int startp = adlen - lenp;
            for (int k = 0; k < lenp; k++) {
                S[k + 96] ^= AD[startp + k];
            }
            S[32] ^= lenp;
        }

        // The encryption
        // In each step of encrypting the plaintext M:
        // XOR the frame bits (FB_pc) of the plaintext with state S,
        // then update the state using keyed permutation P_1024,
        // and finally XOR the 32 bits of the plaintext with the state to obtain the 32-bit ciphertext.
        int mlen = M.length;
        if (mlen >= 32) {
            for (int k = 0; k < mlen / 32; k++) {
                for (int i = 36; i < 39; i++) {
                    S[i] ^= FB_pc[i - 36];
                }
                S = stateUpdate(S, K, 1024);
                for (int i = 0; i < 32; i++) {
                    S[i + 96] ^= M[i + 32 * k];
                }
                for (int i = 0; i < 32; i++) {
                    C[i + 32 * k] = S[i + 64] ^ M[i + 32 * k];
                }
            }
        }

        // Process the remaining partial block of plaintext:
        // If the last block is not a complete block (partial block),
        // XOR the last block with state S and XOR the number of bytes of the plaintext with state S.
        if (mlen % 32 > 0) {
            for (int i = 36; i < 39; i++) {
                S[i] ^= FB_pc[i - 36];
            }
            S = stateUpdate(S, K, 640);
            int lenp = mlen % 32;
            int startp = mlen - lenp;
            for (int i = 0; i < lenp; i++) {
                S[i + 96] ^= M[startp + i];
            }
            for (int i = 0; i < lenp; i++) {
                C[startp + i] = S[i + 64] ^ M[startp + i];
            }
            S[32] ^= lenp;
        }

        return C;
    }
    
      public static long[] tinyjambuDecrypt(long[] S, long[] K, long[] N, long[] T, long[] M, long[] C, long[] AD) {
          
            // FrameBits
        long[] FB_n = {0, 0, 1};
        long[] FB_ad = {0, 1, 1};
        long[] FB_pc = {1, 0, 1};
        long[] FB_f = {1, 1, 1};
          
        // The initialization
        // Key setup
        S =stateUpdate(S, K, 1024);
        
        // Nonce setup
        for (int i = 0; i < 3; i++) {
            long a = 0;
            long b = 0;
            for (int j = 36; j < 39; j++) {
                S[j] = S[j] ^ FB_n[j - 36];
            }
            S = stateUpdate(S, K, 640);
            for (int j = 96; j < 128; j++) {
                S[j] = S[j] ^ N[32 * i + j - 96];
            }
        }
        
        // Processing the associated data
        // Handling complete associated data blocks
        int adlen = AD.length;
        if (adlen >= 32) {
            for (int j = 0; j < adlen / 32; j++) {
                long a = 0;
                long b = 0;
                for (int k = 36; k < 39; k++) {
                    S[k] = S[k] ^ FB_ad[k - 36];
                }
                S = stateUpdate(S, K, 640);
                for (int k = 96; k < 128; k++) {
                    S[k] = S[k] ^ AD[32 * j + k - 96];
                }
            }
        }
        
        // Handling the remaining part of associated data blocks
        if (adlen % 32 > 0) {
            long a = 0;
            long b = 0;
            for (int k = 36; k < 39; k++) {
                S[k] = S[k] ^ FB_ad[k - 36];
            }
            S = stateUpdate(S, K, 640);
            int lenp = adlen % 32;
            int startp = adlen - lenp;
            for (int k = 96; k < 96 + lenp; k++) {
                S[k] = S[k] ^ AD[startp + k - 96];
            }
            S[32] ^= lenp;
        }
        
        // The decryption
        // Handling complete ciphertext blocks
        int clen = C.length;
        if (clen >= 32) {
            for (int k = 0; k < clen / 32; k++) {
                long a = 0;
                long b = 0;
                for (int j = 36; j < 39; j++) {
                    S[j] = S[j] ^ FB_pc[j - 36];
                }
                S = stateUpdate(S, K, 1024);
                for (int j = 96; j < 128; j++) {
                    S[j] = S[j] ^ C[32 * k + j - 96];
                }
                for (int j = 0; j < 32; j++) {
                    M[32 * k + j] = S[64 + j] ^ C[32 * k + j];
                }
            }
        }
        
        // Handling the remaining part of ciphertext blocks
        if (clen % 32 > 0) {
            long a = 0;
            long b = 0;
            for (int j = 36; j < 39; j++) {
                S[j] = S[j] ^ FB_pc[j - 36];
            }
            S = stateUpdate(S, K, 640);
            int lenp = clen % 32;
            int startp = clen - lenp;
            for (int j = 96; j < 96 + lenp; j++) {
                S[j] = S[j] ^ C[startp + j - 96];
            }
            int lenp_c = 0;
            for (int j = startp; j < clen; j++) {
               // System.out.println(startp + " " + clen + " " + j);
                M[startp + j - clen] = S[64 + lenp_c] ^ C[startp + j - clen];
                lenp_c++;
            }
            S[32] ^= lenp;
        }
        
  

        
        
        return M;
    }

    

    public static void main(String[] args) {
        /*int klen = 128;
        long[] S = new long[128];
        long[] K = new long[128];

        Arrays.fill(S, 0x1);
        Arrays.fill(K, 0x1);

        long[] a = stateUpdate(S, K, 600);
        System.out.println(Arrays.toString(a));*/
        long[] S = new long[128];
        long[] K = new long[128];
        Arrays.fill(S, 0x1);
        Arrays.fill(K, 0x1);

        long[] N = new long[96];
        long[] T = new long[64];
        long[] C = new long[200];
        long[] AD = new long[51];
        for(int i = 0; i <= 50; i++) AD[i] = i;
       // long[] M = {73, 116, 32, 105, 115, 32, 97, 32, 112, 108, 97, 99, 101, 32, 119, 104, 101, 114, 101, 32, 107, 105, 110, 100, 108, 121, 32, 97, 102, 102, 101, 99, 116, 105, 111, 110, 115, 32, 101, 120, 105, 115, 116, 32, 97, 109, 111, 110, 103, 32, 97, 108, 108, 116, 104, 101, 32, 109, 101, 109, 98, 101, 114, 115, 32, 111, 102, 32, 116, 104, 101, 32, 102, 97, 109, 105, 108, 121, 46, 32, 84, 104, 101, 32, 112, 97, 114, 101, 110, 116, 115, 32, 116, 97, 107, 101, 32, 103, 111, 111, 100, 99, 97, 114, 101, 32, 111, 102, 32, 116, 104, 101, 105, 114, 32, 99, 104, 105, 108, 100, 114, 101, 110, 44, 97, 110, 100, 32, 116, 104, 101, 32, 99, 104, 105, 108, 100, 114, 101, 110, 32, 97, 114, 101, 32, 105, 110, 116, 101, 114, 101, 115, 116, 101, 100, 105, 110, 32, 116, 104, 101,
       // 2, 97, 99, 116, 105, 118, 105, 116, 105, 101, 115, 32, 111, 102, 32, 116, 104, 101, 105, 114, 32, 112, 97, 114, 101, 110, 116, 115};
       //long[] M = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,15,17,18,19,20,1,2,3,4,5,6,7,8,9,10,11,12,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,15,17,18,19,20,1,2,3,4,5,6,7,8,9,10,11,12};
       long[] M = new long[15];
       for(int i =0; i<15; i++) M[i] = i;
        long[] _M = new long[M.length + 11 + 200];
    
        // Call the tinyjambu method
        tinyjambuEncrypt(S, K, N, T,M, C, AD);
        tinyjambuDecrypt(S, K, N, T, _M, C, AD);
        
        // Print the ciphertext
       // System.out.println(Arrays.toString(C));
        //System.out.println(Arrays.toString(_M));
        System.out.print("Original message: ");
        for(int i = 0; i < M.length; i++) System.out.print(M[i] + " ");
        System.out.print("\nEncrypted Message: ");
        for(int i = 0; i < M.length; i++) System.out.print(String.format("0x%02x ", C[i]));
        System.out.print("\nDecrypted Message: ");
        for(int i = 0; i < M.length; i++) System.out.print(_M[i] + " ");
        System.out.println();
        
    }
}


