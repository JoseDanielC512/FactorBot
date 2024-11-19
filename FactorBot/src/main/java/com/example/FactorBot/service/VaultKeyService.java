package com.example.FactorBot.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class VaultKeyService {

    @Value("${spring.cloud.vault.config.backend}")
    private String vaultBackend;

    @Value("${spring.cloud.vault.config.default-key}")
    private String vaultKeysDirectory; // Ruta de las llaves almacenadas en Vault

    @Value("${jwt.public-key-alias}")
    private String publicKeyAlias;

    @Value("${jwt.private-key-alias}")
    private String privateKeyAlias;

    @Autowired
    private final VaultTemplate vaultTemplate;

    public VaultKeyService(VaultTemplate vaultTemplate) {
        this.vaultTemplate = vaultTemplate;
    }

    public PublicKey getPublicKeyFromVault() throws Exception {
        // Construir la ruta completa a la clave pública
        String vaultPath = vaultBackend + "/" + vaultKeysDirectory + "/" + publicKeyAlias;

        // Recuperar la clave pública desde Vault
        VaultResponse vaultResponse = vaultTemplate.read(vaultPath);

        if (vaultResponse == null || vaultResponse.getData() == null) {
            throw new IllegalArgumentException("No se encontró la clave pública en Vault en la ruta: " + vaultPath);
        }

        // Obtener el valor de la clave pública
        String publicKeyPem = (String) vaultResponse.getData().get(publicKeyAlias);

        // Convertir el formato PEM a PublicKey
        String publicKeyContent = publicKeyPem.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(publicKeyContent);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public PrivateKey getPrivateKeyFromVault() throws Exception {
        // Construir la ruta completa a la clave privada
        String vaultPath = vaultBackend + "/" + vaultKeysDirectory + "/" + privateKeyAlias;

        // Recuperar la clave pública desde Vault
        VaultResponse vaultResponse = vaultTemplate.read(vaultPath);

        if (vaultResponse == null || vaultResponse.getData() == null) {
            throw new IllegalArgumentException("No se encontró la clave privada en Vault en la ruta: " + vaultPath);
        }

        // Obtener el valor de la clave privada
        String privateKeyPem = (String) vaultResponse.getData().get(privateKeyAlias);

        // Convertir el formato PEM a PublicKey
        String privateKeyContent = privateKeyPem.replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(privateKeyContent);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

}