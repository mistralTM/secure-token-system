package org.example.token;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Instant;

public class TokenPayload {
    private static final ObjectMapper mapper = new ObjectMapper();

    private final String data;
    private final String issuer;
    private final long timestamp;

    @JsonCreator
    public TokenPayload(@JsonProperty("data") String data, @JsonProperty("issuer") String issuer, @JsonProperty("timestamp") long timestamp) {
        this.data = data;
        this.issuer = issuer;
        this.timestamp = timestamp;
    }

    public static TokenPayload create(String data, String issuer) {
        return new TokenPayload(data, issuer, Instant.now().getEpochSecond());
    }

    public static TokenPayload fromJson(String json) throws JsonProcessingException {
        return mapper.readValue(json, TokenPayload.class);
    }

    public String toJson() throws JsonProcessingException {
        return mapper.writeValueAsString(this);
    }

    public String getData() {
        return data;
    }

    public String getIssuer() {
        return issuer;
    }

    public long getTimestamp() {
        return timestamp;
    }
}