#include <cstdio>
#include <cstring>
#include <iostream>

#include "rsa.h"

static const char* statusName(RSA::Status st) {
    switch (st) {
    case RSA::Status::Ok:              return "Ok";
    case RSA::Status::InvalidArgument: return "InvalidArgument";
    case RSA::Status::InvalidKey:      return "InvalidKey";
    case RSA::Status::OutOfRange:      return "OutOfRange";
    case RSA::Status::MessageTooLong:  return "MessageTooLong";
    case RSA::Status::DecryptionError: return "DecryptionError";
    case RSA::Status::RngFailure:      return "RngFailure";
    case RSA::Status::FaultDetected:   return "FaultDetected";
    case RSA::Status::BadSignature:    return "BadSignature";
    }
    return "?";
}

static void printHex(const char* title, const std::uint8_t* data, std::size_t len, std::size_t maxBytes) {
    std::printf("%s (%zu байт): ", title, len);
    for (std::size_t i = 0; i < len && i < maxBytes; ++i) std::printf("%02x", data[i]);
    if (len > maxBytes) std::printf("...");
    std::printf("\n");
}

int main() {
    setlocale(LC_ALL, "Russian");
    RSA rsa;

    std::printf("Генерация ключа RSA-2048...\n");
    RSA::Status st = rsa.generateKeys();
    if (st != RSA::Status::Ok) {
        std::printf("Ошибка генерации ключа: %s\n", statusName(st));
        if (st == RSA::Status::RngFailure) {
            std::printf("Не сработал системный источник случайности. Можно передать свой:\n"
                "  rsa.generateKeys(myRng, myCtx), где myRng - bool(void*, void*, size_t).\n");
        }
        return 1;
    }

    std::uint8_t modulus[RSA::kModulusBytes];
    rsa.getModulus(modulus);
    printHex("Модуль n", modulus, sizeof modulus, 16);

    const char* text = "Терпение и труд все я устал";
    const char* label = "demo-v1";
    const std::size_t textLen = std::strlen(text);
    const std::size_t labelLen = std::strlen(label);
    std::printf("Сообщение: \"%s\" (%zu байт)\n", text, textLen);

    std::uint8_t cipher[RSA::kModulusBytes];
    st = rsa.encrypt(reinterpret_cast<const std::uint8_t*>(text), textLen,
        reinterpret_cast<const std::uint8_t*>(label), labelLen, cipher);
    if (st != RSA::Status::Ok) {
        std::printf("Ошибка шифрования: %s\n", statusName(st));
        return 1;
    }
    printHex("Шифртекст", cipher, sizeof cipher, 16);

    std::uint8_t plain[RSA::kMaxMessageBytes + 1]; 
    std::size_t plainLen = 0;
    st = rsa.decrypt(cipher, reinterpret_cast<const std::uint8_t*>(label), labelLen,
        plain, RSA::kMaxMessageBytes, plainLen);
    if (st != RSA::Status::Ok) {
        std::printf("Ошибка расшифрования: %s\n", statusName(st));
        return 1;
    }
    plain[plainLen] = 0;
    std::printf("Расшифровано: \"%s\" (%zu байт)\n", reinterpret_cast<const char*>(plain), plainLen);

    const bool same = plainLen == textLen && std::memcmp(plain, text, textLen) == 0;
    std::printf("Сообщение совпадает с исходным: %s\n", same ? "да" : "НЕТ");

    const char* wrongLabel = "demo-v2";
    std::uint8_t junk[RSA::kMaxMessageBytes];
    std::size_t junkLen = 0;
    st = rsa.decrypt(cipher, reinterpret_cast<const std::uint8_t*>(wrongLabel), std::strlen(wrongLabel),
        junk, sizeof junk, junkLen);
    std::printf("Расшифрование с неверной меткой: %s (длина результата %zu)\n", statusName(st), junkLen);

    cipher[100] ^= 0x01;
    st = rsa.decrypt(cipher, reinterpret_cast<const std::uint8_t*>(label), labelLen,
        junk, sizeof junk, junkLen);
    std::printf("Расшифрование испорченного шифртекста: %s\n", statusName(st));

    return same ? 0 : 1;
}
