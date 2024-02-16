package com.meuscursos.web_security.service;

import com.meuscursos.web_security.model.User;
import com.meuscursos.web_security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository repository;
    @Autowired
    private PasswordEncoder encoder;
    public void createUser(User user){
        logger.info("Criando o usuário...");
        String pass = user.getPassword();
        logger.info("User aantes cryptografia..."+user);
        logger.info("Password antes da cryptografia..."+user.getPassword());
        //criptografando antes de salvar no banco
        user.setPassword(encoder.encode(pass));
        logger.info("Password após da cryptografia..."+user.getPassword());
        logger.info("User após cryptografia..."+user);
        repository.save(user);
    }
}
