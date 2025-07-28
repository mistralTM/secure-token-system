package org.example.encryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class EncryptionService {
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";

    private final SecretKey secretKey;

    public EncryptionService() throws NoSuchAlgorithmException {
        this.secretKey = generateKey();
    }

    public EncryptionService(SecretKey secretKey) {
        if (secretKey == null) {
            throw new IllegalArgumentException("Secret key cannot be null");
        }
        this.secretKey = secretKey;
    }

    private SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    public byte[] encrypt(String data) throws Exception {
        if (data == null || data.isEmpty()) {
            throw new IllegalArgumentException("Data to encrypt cannot be null or empty");
        }

        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        byte[] encrypted = cipher.doFinal(data.getBytes());

        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encrypted.length);
        byteBuffer.put(iv);
        byteBuffer.put(encrypted);

        return byteBuffer.array();
    }

    public String decrypt(byte[] encryptedData) throws Exception {
        if (encryptedData == null || encryptedData.length == 0) {
            throw new IllegalArgumentException("Encrypted data cannot be null or empty");
        }

        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);

        byte[] iv = new byte[GCM_IV_LENGTH];
        byteBuffer.get(iv);

        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        byte[] decrypted = cipher.doFinal(cipherText);
        return new String(decrypted);
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public String exportKey() {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }
}