package com.example.ass1;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;


public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the file path (do not use quote marks): ");
        String filePath = scanner.nextLine();
        scanner.close();

        EncryptionDecryptionApp example = new EncryptionDecryptionApp();
        example.performEncryptionDecryption(filePath);

    }
}

class EncryptionDecryptionApp {

    // Define AES encryption key
    private static final byte[] AES_KEY = generateAESKey();

    public void performEncryptionDecryption( String filePath) {
        try {
            // Read plaintext from the file
            String plaintext = readPlainTextFromFile(filePath);

            // Encrypt the plaintext
            byte[] encryptedBytes = encryptAES(plaintext);
            String encryptedText = base64Encode(encryptedBytes);

            System.out.println("Encrypted text: " + encryptedText);

            // Decrypt the ciphertext
            byte[] decryptedBytes = decryptAES(base64Decode(encryptedText));
            String decryptedText = new String(decryptedBytes);

            System.out.println("Decrypted text: " + decryptedText);
        } catch (Exception e) {
            System.out.println("Exception occurred: " + e.getMessage());
        }
    }

    // Generate AES encryption key
    private static byte[] generateAESKey() {
        byte[] key = new byte[16]; // AES key size is 128 bits
        new SecureRandom().nextBytes(key);
        return key;
    }

    // Encrypt plaintext using AES
    private static byte[] encryptAES(String plaintext) throws Exception {
        byte[] plaintextBytes = plaintext.getBytes();
        for (int i = 0; i < plaintextBytes.length; i++) {
            plaintextBytes[i] ^= AES_KEY[i % AES_KEY.length];
        }
        return plaintextBytes;
    }

    // Decrypt ciphertext using AES
    private static byte[] decryptAES(byte[] ciphertext) throws Exception {
        byte[] decryptedBytes = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            decryptedBytes[i] = (byte) (ciphertext[i] ^ AES_KEY[i % AES_KEY.length]);
        }
        return decryptedBytes;
    }

    // Base64 encode
    private static String base64Encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    // Base64 decode
    private static byte[] base64Decode(String encodedText) {
        return Base64.getDecoder().decode(encodedText);
    }

    // Read plaintext from a file
    private static String readPlainTextFromFile(String filePath) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
        }
        return sb.toString();
    }
}
