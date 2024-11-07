package dev.wayne.encryption.service;

import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public interface CryptoService {

    String encrypt(String message, String password);

    String encryptMap(Map<String, String> data, String password);

    String decrypt(String data, String password);

    Map<String, String> decryptMap(String data, String password);
}
