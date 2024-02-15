package com.meuscursos.web_security;


import com.meuscursos.web_security.model.User;
import com.meuscursos.web_security.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class StartApp implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(StartApp.class);
    @Autowired
    private UserRepository repository;
    @Transactional
    @Override
    public void run(String... args) throws Exception {

        logger.info("Iniciando a inicialização da aplicação...");


        User user = repository.findByUsername("admin");
        if(user==null){
            logger.info("Criando usuário 'admin'...");
            user = new User();
            user.setName("ADMIN");
            user.setUsername("admin");
            user.setPassword("master123");
            user.getRoles().add("MANAGERS");
            repository.save(user);
            logger.info("Usuário 'admin' criado com sucesso.");
        }
        User user2 = repository.findByUsername("user");
        if(user2 ==null){
            logger.info("Criando usuário 'user'...");
            user2 = new User();
            user2.setName("USER");
            user2.setUsername("user");
            user2.setPassword("user123");
            user2.getRoles().add("USERS");
            repository.save(user2);
            logger.info("Usuário 'user' criado com sucesso.");
        }
        logger.info("Inicialização da aplicação concluída.");
    }
}
