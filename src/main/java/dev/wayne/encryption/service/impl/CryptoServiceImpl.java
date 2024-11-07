package dev.wayne.encryption.service.impl;

import dev.wayne.encryption.exception.ApiException;
import dev.wayne.encryption.exception.ChaCha20UtilException;
import dev.wayne.encryption.service.CryptoService;
import dev.wayne.encryption.util.ChaCha20Util;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class CryptoServiceImpl implements CryptoService {

    private final ChaCha20Util chaCha20Util;

    @Override
    public String encrypt(String message, String password) {
        try {
            return chaCha20Util.convertingFromAnEncryptedString(message, password, 1);
        } catch (ChaCha20UtilException e) {
            throw new ApiException(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Произошла ошибка шифрования: " + e.getMessage());
        }
    }

    @Override
    public String encryptMap(Map<String, String> data, String password) {
        try {
            return chaCha20Util.convertingFromAnEncryptedString(data, password, 1);
        } catch (ChaCha20UtilException e) {
            throw new ApiException(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Произошла ошибка шифрования: " + e.getMessage());
        }
    }

    @Override
    public String decrypt(String data, String password) {
        try {
            return chaCha20Util.convertingFromAnDecryptedString(data, password, 1);
        } catch (ChaCha20UtilException e) {
            throw new ApiException(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Произошла ошибка расшифровки: " + e.getMessage());
        }
    }

    @Override
    public Map<String, String> decryptMap(String data, String password) {
        try {
            return chaCha20Util.convertingFromAnDecryptedMap(data, password, 1);
        } catch (ChaCha20UtilException e) {
            throw new ApiException(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Произошла ошибка расшифровки: " + e.getMessage());
        }
    }
}
