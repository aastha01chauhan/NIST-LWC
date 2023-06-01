import java.util.Arrays;

class elephant {
  public static final int BLOCK_SIZE = 20;
  public static final int CRYPTO_KEYBYTES = 16;
  public static final int CRYPTO_NSECBYTES = 0;
  public static final int CRYPTO_NPUBBYTES = 12;
  public static final int CRYPTO_ABYTES = 8;
  public static final boolean CRYPTO_NOOVERLAP = true;

  public static final int nBits = 160;
  public static final int nSBox = 20;
  public static final int nRounds = 80;
  public static final int lfsrIV = 0x75;

  public static int GET_BIT(int x, int y) {
    return (x >> y) & 0x1;
  }

  public static final int sBoxLayer[] = {0xee, 0xed, 0xeb, 0xe0, 0xe2, 0xe1, 0xe4, 0xef, 0xe7, 0xea, 0xe8,
      0xe5, 0xe9, 0xec, 0xe3, 0xe6, 0xde, 0xdd, 0xdb, 0xd0, 0xd2, 0xd1, 0xd4, 0xdf, 0xd7, 0xda, 0xd8, 0xd5,
      0xd9, 0xdc, 0xd3, 0xd6, 0xbe, 0xbd, 0xbb, 0xb0, 0xb2, 0xb1, 0xb4, 0xbf, 0xb7, 0xba, 0xb8, 0xb5, 0xb9,
      0xbc, 0xb3, 0xb6, 0x0e, 0x0d, 0x0b, 0x00, 0x02, 0x01, 0x04, 0x0f, 0x07, 0x0a, 0x08, 0x05, 0x09, 0x0c,
      0x03, 0x06, 0x2e, 0x2d, 0x2b, 0x20, 0x22, 0x21, 0x24, 0x2f, 0x27, 0x2a, 0x28, 0x25, 0x29, 0x2c, 0x23,
      0x26, 0x1e, 0x1d, 0x1b, 0x10, 0x12, 0x11, 0x14, 0x1f, 0x17, 0x1a, 0x18, 0x15, 0x19, 0x1c, 0x13, 0x16,
      0x4e, 0x4d, 0x4b, 0x40, 0x42, 0x41, 0x44, 0x4f, 0x47, 0x4a, 0x48, 0x45, 0x49, 0x4c, 0x43, 0x46, 0xfe,
      0xfd, 0xfb, 0xf0, 0xf2, 0xf1, 0xf4, 0xff, 0xf7, 0xfa, 0xf8, 0xf5, 0xf9, 0xfc, 0xf3, 0xf6, 0x7e, 0x7d,
      0x7b, 0x70, 0x72, 0x71, 0x74, 0x7f, 0x77, 0x7a, 0x78, 0x75, 0x79, 0x7c, 0x73, 0x76, 0xae, 0xad, 0xab,
      0xa0, 0xa2, 0xa1, 0xa4, 0xaf, 0xa7, 0xaa, 0xa8, 0xa5, 0xa9, 0xac, 0xa3, 0xa6, 0x8e, 0x8d, 0x8b, 0x80,
      0x82, 0x81, 0x84, 0x8f, 0x87, 0x8a, 0x88, 0x85, 0x89, 0x8c, 0x83, 0x86, 0x5e, 0x5d, 0x5b, 0x50, 0x52,
      0x51, 0x54, 0x5f, 0x57, 0x5a, 0x58, 0x55, 0x59, 0x5c, 0x53, 0x56, 0x9e, 0x9d, 0x9b, 0x90, 0x92, 0x91,
      0x94, 0x9f, 0x97, 0x9a, 0x98, 0x95, 0x99, 0x9c, 0x93, 0x96, 0xce, 0xcd, 0xcb, 0xc0, 0xc2, 0xc1, 0xc4,
      0xcf, 0xc7, 0xca, 0xc8, 0xc5, 0xc9, 0xcc, 0xc3, 0xc6, 0x3e, 0x3d, 0x3b, 0x30, 0x32, 0x31, 0x34, 0x3f,
      0x37, 0x3a, 0x38, 0x35, 0x39, 0x3c, 0x33, 0x36, 0x6e, 0x6d, 0x6b, 0x60, 0x62, 0x61, 0x64, 0x6f, 0x67,
      0x6a, 0x68, 0x65, 0x69, 0x6c, 0x63, 0x66};

  public static void PrintState(int[] state) {
    for (int i = nSBox - 1; i >= 0; i--) {
      System.out.printf("%02X ", state[i]);
    }
    System.out.println();
  }

  public static int lCounter(int lfsr) {
    lfsr = ((lfsr << 1) | (((0x40 & lfsr) >> 6) ^ ((0x20 & lfsr) >> 5)));
    lfsr &= 0x7f;
    return lfsr;
  }

  public static int retnuoCl(int lfsr) {
    lfsr = ((lfsr & 0x01) << 7) | ((lfsr & 0x02) << 5) | ((lfsr & 0x04) << 3) | ((lfsr & 0x08) << 1)
        | ((lfsr & 0x10) >> 1) | ((lfsr & 0x20) >> 3) | ((lfsr & 0x40) >> 5) | ((lfsr & 0x80) >> 7);

    return lfsr;
  }

  public static int Pi(int i) {
    if (i != nBits - 1) {
      return (i * nBits / 4) % (nBits - 1);
    } else {
      return nBits - 1;
    }
  }

  public static void pLayer(int[] state) {
    int permutedBitNo;
    int[] tmp = new int[nSBox];

    for (int i = 0; i < nSBox; i++) {
      tmp[i] = 0;
    }

    for (int i = 0; i < nSBox; i++) {
      for (int j = 0; j < 8; j++) {
        int x = GET_BIT(state[i], j);
        permutedBitNo = Pi(8 * i + j);
        int y = permutedBitNo / 8;
        tmp[y] ^= x << (permutedBitNo - 8 * y);
      }
    }

    System.arraycopy(tmp, 0, state, 0, nSBox);
  }

  public static void permutation(int[] state, boolean printState) {
    int IV = lfsrIV;
    int INV_IV;

    for (int i = 0; i < nRounds; i++) {
      if (printState) {
        System.out.printf("%3d\t", i);
        PrintState(state);
      }

      /* Add counter values */
      state[0] ^= IV;
      INV_IV = retnuoCl(IV);
      state[nSBox - 1] ^= INV_IV;
      IV = lCounter(IV);

      /* sBoxLayer layer */
      for (int j = 0; j < nSBox; j++) {
        state[j] = sBoxLayer[state[j] % 256];
      }

      /* pLayer */
      pLayer(state);

      if (printState) {
        System.out.printf("%3d\t", i);
        PrintState(state);
      }
    }
  }

  public static int rotl3(int b) {
    return (b << 3) | (b >> 5);
  }

  public static int constcmp(int[] a, int[] b, int offset, int length) {
    int r = 0;

    for (int i = offset; i < length; ++i) {
      r |= a[i] ^ b[i];
    }
    return r;
  }

  public static void lfsrStep(int[] output, int[] input) {
    int temp = rotl3(input[0]) ^ (input[3] << 7) ^ (input[13] >> 7);

    for (int i = 0; i < BLOCK_SIZE - 1; ++i) {
      output[i] = input[i + 1];
    }

    output[BLOCK_SIZE - 1] = temp;
  }

  public static void xorBlock(int[] state, int[] block, int size) {
    for (int i = 0; i < size; ++i) {
      state[i] ^= block[i];
    }
  }

  public static void getAdBlock(int[] output, int[] ad, int adlen, int[] npub, int i) {
    int len = 0;

    // First block contains nonce
    // Remark: nonce may not be longer then BLOCK_SIZE
    if (i == 0) {
      System.arraycopy(npub, 0, output, len, CRYPTO_NPUBBYTES);
      len += CRYPTO_NPUBBYTES;
    }

    final int block_offset = i * BLOCK_SIZE - ((i != 0) ? 1 : 0) * CRYPTO_NPUBBYTES;

    // If adlen is divisible by BLOCK_SIZE, add an additional padding block
    if (i != 0 && block_offset == adlen) {
      Arrays.fill(output, 0, BLOCK_SIZE, (byte) 0x00);
      output[0] = (byte) 0x01;
      return;
    }

    final int r_outlen = BLOCK_SIZE - len;
    final int r_adlen = adlen - block_offset;

    // Fill with associated data if available
    if (r_outlen <= r_adlen) { // enough AD
      System.arraycopy(ad, block_offset, output, len, r_outlen);
    } else { // not enough AD, need to pad
      if (r_adlen > 0) // ad might be nullptr
        System.arraycopy(ad, block_offset, output, len, r_adlen);
      Arrays.fill(output, len + r_adlen, len + r_adlen + r_outlen - r_adlen, (byte) 0x00);
      output[len + r_adlen] = (byte) 0x01;
    }
  }

  public static void getCBlock(int[] output, int[] c, int clen, int i) {
    int blockOffset = i * BLOCK_SIZE;
    // If clen is divisible by BLOCK_SIZE, add an additional padding block
    if (blockOffset == clen) {
      Arrays.fill(output, 0, BLOCK_SIZE, 0);
      output[0] = 1;
      return;
    }
    int rClen = clen - blockOffset;
    // Fill with ciphertext if available
    if (BLOCK_SIZE <= rClen) { // enough ciphertext
      System.arraycopy(c, blockOffset, output, 0, BLOCK_SIZE);
    } else { // not enough ciphertext, need to pad
      if (rClen > 0) // c might be nullptr
        System.arraycopy(c, blockOffset, output, 0, rClen);
      Arrays.fill(output, rClen, BLOCK_SIZE, 0);
      output[rClen] = 1;
    }
  }

  public static void cryptoAeadImpl(
      int[] c, int[] tag, int[] m, int mlen, int[] ad, int adlen, int[] npub, int[] k, boolean encrypt) {
    // Compute number of blocks
    final int nblocksC = 1 + mlen / BLOCK_SIZE;
    final int nblocksM = ((mlen % BLOCK_SIZE) != 0) ? nblocksC : nblocksC - 1;
    final int nblocksAd = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE;
    final int nbIt = (nblocksC + 1 > nblocksAd - 1) ? nblocksC + 1 : nblocksAd - 1;

    // Storage for the expanded key L
    int[] expandedKey = new int[BLOCK_SIZE];
    System.arraycopy(k, 0, expandedKey, 0, CRYPTO_KEYBYTES);
    permutation(expandedKey, false);

    int[] maskBuffer1 = new int[BLOCK_SIZE];
    int[] maskBuffer2 = new int[BLOCK_SIZE];
    int[] maskBuffer3 = new int[BLOCK_SIZE];
    System.arraycopy(expandedKey, 0, maskBuffer2, 0, BLOCK_SIZE);

    int[] previousMask = maskBuffer1;
    int[] currentMask = maskBuffer2;
    int[] nextMask = maskBuffer3;

    // Buffer to store current ciphertext/AD block
    int[] buffer = new int[BLOCK_SIZE];

    // Tag buffer and initialization of tag to first AD block
    int[] tagBuffer = new int[BLOCK_SIZE];
    getAdBlock(tagBuffer, ad, adlen, npub, 0);

    int offset = 0;
    for (int i = 0; i < nbIt; ++i) {
      // Compute mask for the next message
      lfsrStep(nextMask, currentMask);

      if (i < nblocksM) {
        // Compute ciphertext block
        System.arraycopy(npub, 0, buffer, 0, CRYPTO_NPUBBYTES);
        Arrays.fill(buffer, CRYPTO_NPUBBYTES, BLOCK_SIZE, 0);
        xorBlock(buffer, currentMask, BLOCK_SIZE);
        xorBlock(buffer, nextMask, BLOCK_SIZE);
        permutation(buffer, false);
        xorBlock(buffer, currentMask, BLOCK_SIZE);
        xorBlock(buffer, nextMask, BLOCK_SIZE);
        final int rSize = (i == nblocksM - 1) ? mlen - offset : BLOCK_SIZE;
        int[] newM = new int[m.length];
        System.arraycopy(m, offset, newM, 0, rSize);
        xorBlock(buffer, newM, rSize);
        System.arraycopy(buffer, 0, c, offset, rSize);
      }

      if (i > 0 && i <= nblocksC) {
        // Compute tag for ciphertext block
        getCBlock(buffer, encrypt ? c : m, mlen, i - 1);
        xorBlock(buffer, previousMask, BLOCK_SIZE);
        xorBlock(buffer, nextMask, BLOCK_SIZE);
        permutation(buffer, false);
        xorBlock(buffer, previousMask, BLOCK_SIZE);
        xorBlock(buffer, nextMask, BLOCK_SIZE);
        xorBlock(tagBuffer, buffer, BLOCK_SIZE);
      }

      if (i + 1 < nblocksAd) {
        getAdBlock(buffer, ad, adlen, npub, i + 1);
        xorBlock(buffer, nextMask, BLOCK_SIZE);
        permutation(buffer, false);
        xorBlock(buffer, nextMask, BLOCK_SIZE);
        xorBlock(tagBuffer, buffer, BLOCK_SIZE);
      }

      // Cyclically shift the mask buffers
      // Value of next_mask will be computed in the next iteration
      final int[] temp = previousMask;
      previousMask = currentMask;
      currentMask = nextMask;
      nextMask = temp;

      offset += BLOCK_SIZE;
    }

    // Compute tag
    xorBlock(tagBuffer, expandedKey, BLOCK_SIZE);
    permutation(tagBuffer, false);
    xorBlock(tagBuffer, expandedKey, BLOCK_SIZE);
    System.arraycopy(tagBuffer, 0, tag, 0, CRYPTO_ABYTES);
  }

  // Remark: c must be at least mlen + CRYPTO_ABYTES long
  public static int cryptoAeadEncrypt(
      int[] c, int[] clen, int[] m, int mlen, int[] ad, int adlen, int[] nsec, int[] npub, int[] k) {
    // Calculate the length of the ciphertext
    clen[0] = mlen + CRYPTO_ABYTES;

    // Create a buffer for the tag
    int[] tag = new int[CRYPTO_ABYTES];

    // Encrypt the message and AD
    cryptoAeadImpl(c, tag, m, mlen, ad, adlen, npub, k, true);

    // Copy the tag to the end of the ciphertext
    System.arraycopy(tag, 0, c, mlen, CRYPTO_ABYTES);

    return 0;
  }

  public static int cryptoAeadDecrypt(
      int[] m, int mlen, int[] c, int clen, int[] ad, int adlen, int[] nsec, int[] npub, int[] k) {
    // Check if the ciphertext is too short.
    if (clen < CRYPTO_ABYTES) {
      return -1;
    }

    // Set the plaintext length.
    mlen = clen - CRYPTO_ABYTES;

    // Create a buffer for the authentication tag.
    int[] tag = new int[CRYPTO_ABYTES];

    // Decrypt the message.
    cryptoAeadImpl(m, tag, c, mlen, ad, adlen, npub, k, false);

    // Compare the authentication tag.
    // return constcmp(c + *mlen, tag) ? 0 : -1;
    return (constcmp(c, tag, mlen, CRYPTO_ABYTES) == 0 ? 0 : -1);
  }

  public static void main(String[] args) {
    int[] c = new int[100];
    int[] clen = new int[2];
    clen[0] = 10;

    int[] m = new int[] {1, 2, 3, 4, 5, 6, 7};
    int mlen = 7;

    int[] ad = new int[] {10, 11, 12, 13, 14};
    int adlen = 5;

    int[] nsec = new int[100];
    int[] npub = new int[100];
    int[] k = new int[100];

    System.out.print("Original Message: ");
    for (int i = 0; i < mlen; i++) System.out.print(m[i] + " ");
    System.out.println();

    cryptoAeadEncrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);
    System.out.print("Encrypted Message: ");
    for (int i = 0; i < clen[0]; i++) System.out.print(String.format("0x%02x ", c[i]));
    System.out.println();

    int[] _m = new int[mlen];
    int _mlen = mlen;
    cryptoAeadDecrypt(_m, _mlen, c, clen[0], ad, adlen, nsec, npub, k);
    System.out.print("Decrypted Message: ");
    for (int i = 0; i < mlen; i++) System.out.print(String.format("%d ", _m[i]));
    System.out.println();
  }
}