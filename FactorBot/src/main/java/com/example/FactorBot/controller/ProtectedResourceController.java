package com.example.FactorBot.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/resource")
public class ProtectedResourceController {

    @GetMapping
    public ResponseEntity<?> getProtectedResource() {
        // Extraer el principal de la seguridad de Spring
        String username = "Unknown";
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        // Si el principal es un objeto de tipo User, extraemos el nombre de usuario
        if (principal instanceof User) {
            username = ((User) principal).getUsername();
        }

        // Simular un recurso protegido
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Access to protected resource granted!");
        response.put("username", username);

        return ResponseEntity.ok(response);
    }
}