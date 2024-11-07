package dev.wayne.encryption.util;

import dev.wayne.encryption.exception.ChaCha20UtilException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

@Component
public class ChaCha20Util {

    @Value("${validation.container}")
    private String valid;

    public byte[] convertingFromAnEncryptedByte(Map<String, String> info, String password, int counter) throws ChaCha20UtilException {
        try {
            return encrypt(convertToByteUtf8(info.toString()), password.getBytes(StandardCharsets.UTF_8), counter);
        } catch (Exception e) {
            throw new ChaCha20UtilException("Encryption error. Reason: " + e.getMessage(), e.getCause());
        }
    }

    public byte[] convertingFromAnEncryptedByte(String info, String password, int counter) throws ChaCha20UtilException {
        try {
            return encrypt(convertToByteUtf8(info), password.getBytes(StandardCharsets.UTF_8), counter);
        } catch (Exception e) {
            throw new ChaCha20UtilException("Encryption error. Reason: " + e.getMessage(), e.getCause());
        }
    }

    public byte[] convertingFromAnEncryptedByte(byte[] info, String password, int counter) throws ChaCha20UtilException {
        try {
            return encrypt(convertToByteUtf8(info), password.getBytes(StandardCharsets.UTF_8), counter);
        } catch (Exception e) {
            throw new ChaCha20UtilException("Encryption error. Reason: " + e.getMessage(), e.getCause());
        }
    }

    public String convertingFromAnEncryptedString(Map<String, String> info, String password, int counter) throws ChaCha20UtilException {
        try {
            return convertToStringBase64(encrypt(convertToByteUtf8(info.toString()), password.getBytes(StandardCharsets.UTF_8), counter));
        } catch (Exception e) {
            throw new ChaCha20UtilException("Encryption error. Reason: " + e.getMessage(), e.getCause());
        }
    }

    public String convertingFromAnEncryptedString(String info, String password, int counter) throws ChaCha20UtilException {
        try {
            return convertToStringBase64(encrypt(convertToByteUtf8(info), password.getBytes(StandardCharsets.UTF_8), counter));
        } catch (Exception e) {
            throw new ChaCha20UtilException("Encryption error. Reason: " + e.getMessage(), e.getCause());
        }
    }

    public String convertingFromAnEncryptedString(byte[] info, String password, int counter) throws ChaCha20UtilException {
        try {
            return convertToStringBase64(encrypt(convertToByteUtf8(info), password.getBytes(StandardCharsets.UTF_8), counter));
        } catch (Exception e) {
            throw new ChaCha20UtilException("Encryption error. Reason: " + e.getMessage(), e.getCause());
        }
    }

    public String convertingFromAnDecryptedString(byte[] info, String password, int counter) throws ChaCha20UtilException {
        byte[] decrypt = null;
        try {
            decrypt = decrypt(info, password.getBytes(StandardCharsets.UTF_8), counter);
        } catch (Exception e) {
            throw new ChaCha20UtilException("An error occurred during decryption. Reason: " + e.getMessage(), e.getCause());
        }
        if (containsValid(decrypt)) {
            return new String(removeValid(decrypt), StandardCharsets.UTF_8);
        } else {
            throw new ChaCha20UtilException("Decryption occurred, but the constant value did not pass verification, the transmitted values for decryption are incorrect.");
        }
    }

    public String convertingFromAnDecryptedString(String info, String password, int counter) throws ChaCha20UtilException {
        byte[] decrypt = null;
        try {
            decrypt = decrypt(Base64.getDecoder().decode(info), password.getBytes(StandardCharsets.UTF_8), counter);
        } catch (Exception e) {
            throw new ChaCha20UtilException("An error occurred during decryption. Reason: " + e.getMessage(), e.getCause());
        }
        if (containsValid(decrypt)) {
            return new String(removeValid(decrypt), StandardCharsets.UTF_8);
        } else {
            throw new ChaCha20UtilException("Decryption occurred, but the constant value did not pass verification, the transmitted values for decryption are incorrect.");
        }
    }

    public byte[] convertingFromAnDecryptedByte(byte[] info, String password, int counter) throws ChaCha20UtilException {
        byte[] decrypt = null;
        try {
            decrypt = decrypt(info, password.getBytes(StandardCharsets.UTF_8), counter);
        } catch (Exception e) {
            throw new ChaCha20UtilException("An error occurred during decryption. Reason: " + e.getMessage(), e.getCause());
        }
        if (containsValid(decrypt)) {
            return convertToByteUtf8(removeValid(decrypt));
        } else {
            throw new ChaCha20UtilException("Decryption occurred, but the constant value did not pass verification, the transmitted values for decryption are incorrect.");
        }
    }

    public byte[] convertingFromAnDecryptedByte(String info, String password, int counter) throws ChaCha20UtilException {
        byte[] decrypt = null;
        try {
            decrypt = decrypt(Base64.getDecoder().decode(info), password.getBytes(StandardCharsets.UTF_8), counter);
        } catch (Exception e) {
            throw new ChaCha20UtilException("An error occurred during decryption. Reason: " + e.getMessage(), e.getCause());
        }
        if (containsValid(decrypt)) {
            return convertToByteUtf8(removeValid(decrypt));
        } else {
            throw new ChaCha20UtilException("Decryption occurred, but the constant value did not pass verification, the transmitted values for decryption are incorrect.");
        }
    }

    public Map<String, String> convertingFromAnDecryptedMap(byte[] info, String password, int counter) throws ChaCha20UtilException {
        try {
            return convertStringToMap(convertingFromAnDecryptedString(info, password, counter));
        } catch (Exception e) {
            throw new ChaCha20UtilException("Decryption error. Reason: " + e.getMessage(), e.getCause());
        }
    }

    public Map<String, String> convertingFromAnDecryptedMap(String info, String password, int counter) throws ChaCha20UtilException {
        try {
            return convertStringToMap(convertingFromAnDecryptedString(info, password, counter));
        } catch (Exception e) {
            throw new ChaCha20UtilException("Decryption error. Reason: " + e.getMessage(), e.getCause());
        }
    }

    private byte[] encrypt(byte[] info, byte[] key, int counter) {
        try {
            byte[] nonceBytes = new byte[12];
            Cipher cipher = Cipher.getInstance("ChaCha20");
            ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonceBytes, counter);
            SecretKeySpec keySpec = new SecretKeySpec(convertKey(key), "ChaCha20");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec);
            return cipher.doFinal(concatenateWithValid(info));
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    private byte[] decrypt(byte[] info, byte[] key, int counter) {
        try {
            byte[] nonceBytes = new byte[12];
            Cipher cipher = Cipher.getInstance("ChaCha20");
            ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonceBytes, counter);
            SecretKeySpec keySpec = new SecretKeySpec(convertKey(key), "ChaCha20");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);
            return cipher.doFinal(info);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    private byte[] concatenateWithValid(byte[] info) {
        byte[] validBytes = valid.getBytes(StandardCharsets.UTF_8);
        byte[] combined = new byte[info.length + validBytes.length];
        System.arraycopy(info, 0, combined, 0, info.length);
        System.arraycopy(validBytes, 0, combined, info.length, validBytes.length);
        return combined;
    }

    private byte[] convertKey(byte[] key) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hashedKey = sha256.digest(key);
            if (hashedKey.length == 32) {
                return hashedKey;
            }
            byte[] result = new byte[32];
            System.arraycopy(hashedKey, 0, result, 0, hashedKey.length);
            return result;
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    private boolean containsValid(byte[] decryptedInfo) {
        byte[] validBytes = valid.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i <= decryptedInfo.length - validBytes.length; i++) {
            boolean match = true;
            for (int j = 0; j < validBytes.length; j++) {
                if (decryptedInfo[i + j] != validBytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    }

    private byte[] removeValid(byte[] decryptedInfo) {
        decryptedInfo = Objects.requireNonNull(convertToByteUtf8(decryptedInfo));
        byte[] validBytes = valid.getBytes(StandardCharsets.UTF_8);
        int index = -1;
        for (int i = 0; i <= decryptedInfo.length - validBytes.length; i++) {
            boolean match = true;
            for (int j = 0; j < validBytes.length; j++) {
                if (decryptedInfo[i + j] != validBytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                index = i;
                break;
            }
        }
        if (index != -1) {
            byte[] result = new byte[decryptedInfo.length - validBytes.length];
            System.arraycopy(decryptedInfo, 0, result, 0, index);
            System.arraycopy(decryptedInfo, index + validBytes.length, result, index, decryptedInfo.length - index - validBytes.length);
            return result;
        } else {
            return decryptedInfo;
        }
    }

    private byte[] convertToByteUtf8(byte[] inputBytes) {
        Charset utf8Charset = StandardCharsets.UTF_8;
        CharsetDecoder decoder = utf8Charset.newDecoder();
        CharsetEncoder encoder = utf8Charset.newEncoder();
        try {
            ByteBuffer inputBuffer = ByteBuffer.wrap(inputBytes);
            CharBuffer charBuffer = decoder.decode(inputBuffer);
            ByteBuffer outputBuffer = encoder.encode(charBuffer);

            byte[] utf8Bytes = new byte[outputBuffer.remaining()];
            outputBuffer.get(utf8Bytes);
            return utf8Bytes;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] convertToByteUtf8(String inputBytes) {
        return inputBytes.getBytes(StandardCharsets.UTF_8);
    }

    private String convertToStringBase64(byte[] byteArray) {
        return Base64.getEncoder().encodeToString(byteArray);
    }

    private byte[] convertIdToKey(Long id) {
        return String.valueOf(id).getBytes(StandardCharsets.UTF_8);
    }

    private int convertIdToCount(Long id) {
        try {
            return Math.toIntExact(id);
        } catch (Exception e) {
            return 66659;
        }
    }

    private Map<String, String> convertStringToMap(String stringRepresentation) {
        try {
            stringRepresentation = stringRepresentation.replaceAll("\\{", "").replaceAll("\\}", "");
            Properties properties = new Properties();
            properties.load(new StringReader(stringRepresentation.replaceAll(", ", "\n")));
            Map<String, String> result = new HashMap<>();
            properties.forEach((key, value) -> {
                result.put(key.toString(), value.toString());
            });
            return result;
        } catch (Exception e) {
            throw new RuntimeException("Error converting string to Map", e);
        }
    }
}