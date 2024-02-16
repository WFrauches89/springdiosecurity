package com.meuscursos.web_security.config;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Base64;

@Configuration
@ConfigurationProperties(prefix = "security.config")
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    public static String PREFIX;
    public static String KEY;
    public static Long EXPIRATION;

    @PostConstruct
    public void init() {
        byte[] keyBytes = Keys.secretKeyFor(SignatureAlgorithm.HS512).getEncoded();
        KEY = Base64.getEncoder().encodeToString(keyBytes);
        logger.info("Chave JWT gerada com sucesso.",KEY,keyBytes);
    }

    public void setPrefix(String prefix){
        PREFIX = prefix;
        logger.info("Prefixo JWT configurado: {}", prefix);
    }
    public void setKey(String key){
        KEY = key;
        logger.info("Chave: ",KEY);
    }
    public void setExpiration(Long expiration){

        EXPIRATION = expiration;
        logger.info("Tempo de expiração JWT configurado: {} milissegundos", expiration);

    }
}