package dev.wayne.encryption.controller.impl;

import dev.wayne.encryption.controller.CryptoController;
import dev.wayne.encryption.service.CryptoService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class CryptoControllerImpl implements CryptoController {

    private final CryptoService cryptoService;

    @Override
    public String encrypt(String message, String password) {
        return cryptoService.encrypt(message, password);
    }

    @Override
    public String encryptMap(Map<String, String> data, String password) {
        return cryptoService.encryptMap(data, password);
    }

    @Override
    public String decrypt(String data, String password) {
        return cryptoService.decrypt(data, password);
    }

    @Override
    public Map<String, String> decryptMap(String data, String password) {
        return cryptoService.decryptMap(data, password);
    }
}
