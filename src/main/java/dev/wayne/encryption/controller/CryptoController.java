package dev.wayne.encryption.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/main")
@Tag(name = "main")
@ApiResponse(responseCode = "" + HttpServletResponse.SC_INTERNAL_SERVER_ERROR, description = "Внутренняя ошибка сервера")
public interface CryptoController {

    @Operation(summary = "Зашифровать данные",
            description = "Зашифровать данные")
    @PostMapping("/encrypt")
    String encrypt(
            @Parameter(description = "Сообщение", example = "Hello world", required = true)
            @RequestParam("message") String message,
            @Parameter(description = "Пароль", required = true)
            @RequestParam("password") String password
    );

    @Operation(summary = "Зашифровать данные",
            description = "Зашифровать данные")
    @PostMapping("/encrypt/map")
    String encryptMap(
            @Parameter(description = "Данные", required = true)
            @RequestBody Map<String, String> data,
            @Parameter(description = "Пароль", required = true)
            @RequestParam("password") String password
    );

    @Operation(summary = "Расшифровать данные",
            description = "Расшифровать данные")
    @PostMapping("/decrypt")
    String decrypt(
            @Parameter(description = "Данные", required = true)
            @RequestParam("data") String data,
            @Parameter(description = "Пароль", required = true)
            @RequestParam("password") String password
    );

    @Operation(summary = "Расшифровать данные",
            description = "Расшифровать данные")
    @PostMapping("/decrypt/map")
    Map<String, String> decryptMap(
            @Parameter(description = "Данные", required = true)
            @RequestParam("data") String data,
            @Parameter(description = "Пароль", required = true)
            @RequestParam("password") String password
    );
}
