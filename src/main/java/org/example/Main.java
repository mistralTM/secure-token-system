package org.example;

import org.example.encryption.EncryptionService;
import org.example.keymanagement.KeyManager;
import org.example.signature.SignatureService;
import org.example.token.TokenService;

public class Main {
    public static void main(String[] args) {
        try {
            System.out.println("=== Secure Token System Test ===");

            KeyManager keyManager = new KeyManager();
            EncryptionService encryptionService = new EncryptionService(keyManager.getEncryptionKey());
            SignatureService signatureService = new SignatureService(keyManager.getSignatureKeyPair());
            TokenService tokenService = new TokenService(encryptionService, signatureService);

            String sensitiveData = "user123|admin|session789"; // Теперь содержит символы |
            String issuer = "auth-service";

            System.out.println("Original Data: " + sensitiveData);
            System.out.println("Issuer: " + issuer);

            String token = tokenService.createToken(sensitiveData, issuer);
            System.out.println("\nGenerated Token:\n" + token);

            System.out.println("\nVerifying token...");
            String extracted = tokenService.verifyToken(token, issuer, 30);
            System.out.println("Extracted Data: " + extracted);

            System.out.println("\nTest passed successfully!");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}