package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.core.VaultEndpoint;

@Configuration
public class VaultConfig {

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate(); // Usamos RestTemplate para el enfoque bloqueante
    }

    @Bean
    public VaultTemplate vaultTemplate(RestTemplate restTemplate) {
        // Crear el VaultEndpoint configurando la URL y puerto de Vault
        VaultEndpoint vaultEndpoint = VaultEndpoint.create("http", "127.0.0.1");
        vaultEndpoint.setPort(8200); // Puerto donde se encuentra Vault

        // Configurar el token de autenticación
        String token = "00000000-0000-0000-0000-000000000000"; // Usa tu propio token de autenticación

        // Crear la autenticación usando el token
        TokenAuthentication tokenAuthentication = new TokenAuthentication(token);

        // Crear y devolver el VaultTemplate utilizando RestTemplate
        return new VaultTemplate(vaultEndpoint, tokenAuthentication);
    }
}
