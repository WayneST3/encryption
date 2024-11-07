package dev.wayne.encryption.exception;

import lombok.Getter;

@Getter
public class ApiException extends RuntimeException {

    private int statusCode;  // The error code associated with the exception

    /**
     * Constructor for creating an instance of `ApiException`.
     *
     * @param statusCode The error code associated with the exception
     * @param message    The error message
     */
    public ApiException(int statusCode, String message) {
        super(message);  // Call the superclass constructor to set the error message
        this.statusCode = statusCode;  // Set the error code
    }

    /**
     * Constructor for creating an instance of `ApiException` with a cause.
     *
     * @param statusCode The error code associated with the exception
     * @param message    The error message
     * @param cause      The underlying cause of the exception
     */
    public ApiException(int statusCode, String message, Throwable cause) {
        super(message, cause);  // Call the superclass constructor with an additional cause parameter
        this.statusCode = statusCode;  // Set the error code
    }

    /**
     * Convert the `ApiException` instance to a JSON-like string representation.
     *
     * @return A JSON-like string representation of the exception
     */
    @Override
    public String toString() {
        return "{\n  \"statusCode\": " + statusCode + ",\n  \"message\": \"" + getMessage() + "\"\n}";
    }
}