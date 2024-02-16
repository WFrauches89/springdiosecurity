package com.meuscursos.web_security.config;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JWTFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JWTFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        logger.info("Iniciando filtro JWT...");
        //obtem o token da request com AUTHORIZATION
        String token =  request.getHeader(JWTCreator.HEADER_AUTHORIZATION);
        logger.info("Token JWT recebido na requisição: {}", token);
        //esta implementação só esta validando a integridade do token

        try {
            if(token!=null && !token.isEmpty()) {
                logger.info("Validando integridade do token JWT...");
                JWTObject tokenObject = JWTCreator.create(token,SecurityConfig.PREFIX, SecurityConfig.KEY);
                logger.info("Token JWT validado com sucesso: {}", tokenObject);

                List<SimpleGrantedAuthority> authorities = authorities(tokenObject.getRoles());
                logger.info("Authorities extraídas do token: {}", authorities);

                UsernamePasswordAuthenticationToken userToken =
                        new UsernamePasswordAuthenticationToken(
                                tokenObject.getSubject(),
                                null,
                                authorities);

                SecurityContextHolder.getContext().setAuthentication(userToken);

            }else {
                SecurityContextHolder.clearContext();
                logger.warn("Nenhum token JWT encontrado na requisição. AQUI");
            }
            filterChain.doFilter(request, response);
        }catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException e) {
            logger.error("Erro ao processar token JWT: {}", e.getMessage());
            e.printStackTrace();
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return;
        }
    }
    private List<SimpleGrantedAuthority> authorities(List<String> roles){
        return roles.stream().map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}