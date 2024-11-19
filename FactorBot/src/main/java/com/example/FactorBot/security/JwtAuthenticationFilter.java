package com.example.FactorBot.security;

import com.example.FactorBot.service.VaultKeyService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Date;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private VaultKeyService vaultKeyService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Obtener el token JWT del encabezado Authorization
        String authHeader = request.getHeader("Authorization");

        // Verificar si el encabezado está presente y comienza con "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return; // Detener el filtro si el token no está presente o es inválido
        }

        // Extraer el token (remover "Bearer " del encabezado)
        String token = authHeader.substring(7);

        try {
            // Validar el token
            validateToken(token);

            // Continuar con el siguiente filtro en la cadena
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            // Si el token es inválido, devolver un error 401
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    private void validateToken(String token) throws Exception {
        try {
            // Obtener la clave pública desde Vault
            PublicKey publicKey = vaultKeyService.getPublicKeyFromVault();

            // Verificar el token JWT usando la clave pública
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // Verificar si el token ha expirado
            if (claims.getExpiration().before(new Date())) {
                throw new SecurityException("El token ha expirado");
            }

            // Aquí podrías configurar más lógica, como establecer el usuario autenticado en el contexto
            //SecurityContextHolder.getContext().setAuthentication(
            //        new JwtAuthenticationToken(claims.getSubject(), claims)
            //);

        } catch (Exception e) {
            throw new SecurityException("Error al validar el token JWT", e);
        }
    }
}
