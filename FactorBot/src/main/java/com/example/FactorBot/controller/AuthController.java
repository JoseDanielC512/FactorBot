package com.example.FactorBot.controller;

import com.example.FactorBot.dto.LoginRequest;
import com.example.FactorBot.service.VaultKeyService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.PrivateKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/login")
public class AuthController {

    @Value("${jwt.token.expiration}")
    private long tokenExpiration;

    @Autowired
    private VaultKeyService vaultKeyService;

    @PostMapping
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        // Credenciales hardcodeadas
        String hardcodedUsername = "admin";
        String hardcodedPassword = "password";

        // Validar las credenciales
        if (!hardcodedUsername.equals(loginRequest.getUsername()) ||
                !hardcodedPassword.equals(loginRequest.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciales inválidas");
        }

        try {
            // Obtener la clave privada desde Vault
            PrivateKey privateKey = vaultKeyService.getPrivateKeyFromVault();

            // Generar el token JWT
            Map<String, Object> claims = new HashMap<>();
            claims.put("username", loginRequest.getUsername());
            claims.put("roles", "ROLE_USER");

            String jwt = Jwts.builder()
                    .setClaims(claims)
                    .setSubject(loginRequest.getUsername())
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + tokenExpiration))
                    .signWith(privateKey, SignatureAlgorithm.RS256) // Usar RS256
                    .compact();

            // Responder con el token
            Map<String, String> response = new HashMap<>();
            response.put("token", jwt);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error generando el token");
        }
    }
}