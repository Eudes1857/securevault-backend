package com.securevault.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "crypto")
@Getter
@Setter
public class CryptoProperties {
    private String masterKey;
    private int pbkdf2Iterations = 310_000;
    private int saltLengthBytes = 16;
    private int ivLengthBytes = 12;
}
