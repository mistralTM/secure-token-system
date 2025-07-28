package org.example.signature;

import java.security.*;
import java.util.Base64;

public class SignatureService {
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int RSA_KEY_SIZE = 2048;

    private final KeyPair keyPair;

    public SignatureService() throws NoSuchAlgorithmException {
        this.keyPair = generateKeyPair();
    }

    public SignatureService(KeyPair keyPair) {
        if (keyPair == null) {
            throw new IllegalArgumentException("Key pair cannot be null");
        }
        this.keyPair = keyPair;
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(RSA_KEY_SIZE);
        return keyPairGen.generateKeyPair();
    }

    public byte[] sign(byte[] data) throws Exception {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to sign cannot be null or empty");
        }

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(keyPair.getPrivate());
        signature.update(data);
        return signature.sign();
    }

    public boolean verify(byte[] data, byte[] signatureBytes) throws Exception {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to verify cannot be null or empty");
        }
        if (signatureBytes == null || signatureBytes.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(keyPair.getPublic());
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public String exportPublicKey() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    public String exportPrivateKey() {
        return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
    }
}