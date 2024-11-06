package dev.wayne.encryption.exception;

public class ChaCha20UtilException extends Exception {

    public ChaCha20UtilException() {
        super();
    }

    public ChaCha20UtilException(String message) {
        super(message);
    }

    public ChaCha20UtilException(String message, Throwable cause) {
        super(message, cause);
    }

    public ChaCha20UtilException(Throwable cause) {
        super(cause);
    }
}