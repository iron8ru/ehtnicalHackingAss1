package com.example.ass1;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import java.io.*;
import javax.swing.*;
import java.awt.event.*;


public class Main {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                showFileChooser();
            }
        });
    }

    private static void showFileChooser() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Choose a file for encryption");
        int userSelection = fileChooser.showOpenDialog(null);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            String filePath = selectedFile.getAbsolutePath();
            showKeyDirectoryChooser(filePath);
        }
    }

    private static void showKeyDirectoryChooser(String filePath) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Choose a directory to save the key file");
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int userSelection = fileChooser.showSaveDialog(null);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File selectedDirectory = fileChooser.getSelectedFile();
            String keyDirectory = selectedDirectory.getAbsolutePath();
            EncryptionDecryptionApp example = new EncryptionDecryptionApp();
            example.performEncryptionDecryption(filePath, keyDirectory);
        }
    }
}

class EncryptionDecryptionApp {

    // Define AES encryption key
    private static final byte[] AES_KEY = generateAESKey();

    public void performEncryptionDecryption(String filePath, String keyDirectory) {
        try {
            // Read plaintext from the file
            String plaintext = readPlainTextFromFile(filePath);

            // Encrypt the plaintext
            byte[] encryptedBytes = encryptAES(plaintext);
            String encryptedText = base64Encode(encryptedBytes);

            // Construct the new file path for encrypted file
            String encryptedFilePath = constructEncryptedFilePath(filePath);

            // Save encrypted text to a new file
            saveToFile(encryptedFilePath, encryptedText);

            // Save the AES key to a file in the specified directory
            String keyFilePath = constructKeyFilePath(keyDirectory);
            saveKeyToFile(keyFilePath, AES_KEY);

            // Display a message to the user
            JOptionPane.showMessageDialog(null, "Your encrypted file is saved at: " + encryptedFilePath + "\nYour AES key is saved at: " + keyFilePath);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "Exception occurred: " + e.getMessage());
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

    // Base64 encode
    private static String base64Encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
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

    // Construct the path for the encrypted file
    private static String constructEncryptedFilePath(String originalFilePath) {
        // Extract the file name and directory
        String directory = originalFilePath.substring(0, originalFilePath.lastIndexOf(File.separator) + 1);
        String fileName = originalFilePath.substring(originalFilePath.lastIndexOf(File.separator) + 1);

        // Append "Encrypted_" to the file name
        String encryptedFileName = "Encrypted_" + fileName;

        // Construct the encrypted file path
        return directory + encryptedFileName;
    }

    // Construct the path for the key file
    private static String constructKeyFilePath(String keyDirectory) {
        return keyDirectory + File.separator + "key.txt";
    }

    // Save text to a file
    private static void saveToFile(String filePath, String text) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            writer.write(text);
        }
    }

    // Save AES key to a file
    private static void saveKeyToFile(String filePath, byte[] key) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(key);
        }
    }
}
