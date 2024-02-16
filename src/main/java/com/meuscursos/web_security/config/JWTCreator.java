package com.meuscursos.web_security.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.util.List;
import java.util.stream.Collectors;

public class JWTCreator {
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String ROLES_AUTHORITIES = "authorities";

    private static final Logger logger = LoggerFactory.getLogger(JWTCreator.class);

    public static String create(String prefix,String key, JWTObject jwtObject) {
        logger.info("Criando token JWT...");
        logger.info("Prefixo: " + prefix);
        logger.info("Chave: " + key);
        logger.info("Objeto JWT: " + jwtObject);

        String token = Jwts.builder()
                .setSubject(jwtObject.getSubject())
                .setIssuedAt(jwtObject.getIssuedAt())
                .setExpiration(jwtObject.getExpiration())
                .claim(ROLES_AUTHORITIES, checkRoles(jwtObject.getRoles()))
                .signWith(SignatureAlgorithm.HS512, key)
                .compact();
        logger.info("Token JWT criado: " + token);

        return prefix + " " + token;
    }
    public static JWTObject create(String token,String prefix,String key)
            throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException {

        logger.info("Analisando token JWT...");
        logger.info("Token recebido: " + token);

        token = token.replace(" ", "");
        JWTObject object = new JWTObject();
        token = token.replace(prefix, "");
        Claims claims = Jwts.parser().setSigningKey(key).build().parseClaimsJws(token).getBody();
        object.setSubject(claims.getSubject());
        object.setExpiration(claims.getExpiration());
        object.setIssuedAt(claims.getIssuedAt());
        object.setRoles((List) claims.get(ROLES_AUTHORITIES));


        logger.info("Assunto: " + object.getSubject());
        logger.info("Data de expiração: " + object.getExpiration());
        logger.info("Funções/autorizações: " + object.getRoles());

        return object;

    }
    private static List<String> checkRoles(List<String> roles) {
        return roles.stream().map(s -> "ROLE_".concat(s.replaceAll("ROLE_",""))).collect(Collectors.toList());
    }


}