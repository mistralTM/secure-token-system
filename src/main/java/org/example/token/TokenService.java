package org.example.token;

import org.example.encryption.EncryptionService;
import org.example.signature.SignatureService;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Base64;

public class TokenService {
    private static final int RSA_SIGNATURE_LENGTH = 256;

    private final EncryptionService encryptionService;
    private final SignatureService signatureService;

    public TokenService(EncryptionService encryptionService, SignatureService signatureService) {
        this.encryptionService = encryptionService;
        this.signatureService = signatureService;
    }

    public String createToken(String sensitiveData, String issuer) throws Exception {
        TokenPayload payload = TokenPayload.create(sensitiveData, issuer);
        String payloadJson = payload.toJson();

        byte[] encryptedData = encryptionService.encrypt(payloadJson);
        byte[] signature = signatureService.sign(encryptedData);

        ByteBuffer byteBuffer = ByteBuffer.allocate(signature.length + encryptedData.length);
        byteBuffer.put(signature);
        byteBuffer.put(encryptedData);

        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    public String verifyToken(String secureToken, String expectedIssuer, long maxTokenAgeSeconds) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(secureToken);

        ByteBuffer byteBuffer = ByteBuffer.wrap(decoded);
        byte[] signature = new byte[RSA_SIGNATURE_LENGTH];
        byteBuffer.get(signature);
        byte[] encryptedData = new byte[byteBuffer.remaining()];
        byteBuffer.get(encryptedData);

        if (!signatureService.verify(encryptedData, signature)) {
            throw new SecurityException("Invalid token signature");
        }

        String payloadJson = encryptionService.decrypt(encryptedData);
        TokenPayload payload = TokenPayload.fromJson(payloadJson);

        if (!payload.getIssuer().equals(expectedIssuer)) {
            throw new SecurityException("Token issuer mismatch. Expected: " + expectedIssuer + ", got: " + payload.getIssuer());
        }

        long currentTime = Instant.now().getEpochSecond();
        if (currentTime - payload.getTimestamp() > maxTokenAgeSeconds) {
            throw new SecurityException("Token expired. Issued: " + payload.getTimestamp() + ", current: " + currentTime);
        }

        return payload.getData();
    }
}