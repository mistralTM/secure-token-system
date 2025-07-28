package org.example.keymanagement;

import org.example.encryption.EncryptionService;
import org.example.signature.SignatureService;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class KeyManager {
    private final SecretKey encryptionKey;
    private final KeyPair signatureKeyPair;

    public KeyManager() throws NoSuchAlgorithmException {
        this.encryptionKey = new EncryptionService().getSecretKey();
        this.signatureKeyPair = new SignatureService().getKeyPair();
    }

    public KeyManager(SecretKey encryptionKey, KeyPair signatureKeyPair) {
        if (encryptionKey == null || signatureKeyPair == null) {
            throw new IllegalArgumentException("Keys cannot be null");
        }
        this.encryptionKey = encryptionKey;
        this.signatureKeyPair = signatureKeyPair;
    }

    public SecretKey getEncryptionKey() {
        return encryptionKey;
    }

    public KeyPair getSignatureKeyPair() {
        return signatureKeyPair;
    }
}