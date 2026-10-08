#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstring>
#include "Calculator.h"
#include "Belt.h"
#include "BeltGcm.h"
using namespace std;

static string toHex(const uint8_t* d, size_t len) {
    ostringstream ss;
    for (size_t i = 0; i < len; ++i)
        ss << hex << setw(2) << setfill('0') << (int)d[i];
    return ss.str();
}

int main() {
    setlocale(LC_ALL, "Russian");

    Calculator calc;
    cout << "Сложение:  " << hex << (int)calc.gf_add(0x57, 0x83) << "\n";
    cout << "Умножение: " << hex << (int)calc.gf_mul(0x57, 0x83) << "\n";
    cout << "Инверсия:  " << hex << (int)calc.gf_inv(0x57) << dec << "\n\n";

    Belt belt;

    uint8_t keyBytes[BELT_KEY_MAX] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    size_t keyLen = 16;
    uint32_t key[8];
    belt.keyExpand(keyBytes, keyLen, key);

    BeltGcm gcm(key);

    uint8_t iv[GCM_IV_MAX] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B
    };
    size_t ivLen = 12;

    string msg = "Secret message";
    uint8_t plaintext[GCM_MAX_DATA] = { 0 };
    size_t ptLen = msg.size();
    for (size_t i = 0; i < ptLen; ++i)
        plaintext[i] = static_cast<uint8_t>(msg[i]);

    uint8_t aad[GCM_MAX_DATA] = { 0 };
    aad[0] = 'h'; aad[1] = 'd'; aad[2] = 'r';
    size_t aadLen = 3;

    cout << "Открытый текст: " << msg << "\n";
    cout << "                (hex: " << toHex(plaintext, ptLen) << ")\n\n";

    BeltGcm::Encrypted enc;
    gcm.encrypt(iv, ivLen, plaintext, ptLen, aad, aadLen, enc);

    cout << "Зашифровано:    " << toHex(enc.ciphertext, enc.ciphertextLen) << "\n";
    cout << "Тег аутентификации: " << toHex(enc.tag, 16) << "\n\n";

    uint8_t decrypted[GCM_MAX_DATA] = { 0 };
    size_t decLen = 0;
    bool ok = gcm.decrypt(iv, ivLen,
        enc.ciphertext, enc.ciphertextLen,
        aad, aadLen,
        enc.tag,
        decrypted, decLen);

    string decMsg(reinterpret_cast<char*>(decrypted), decLen);

    cout << "Расшифровано:   " << decMsg << "\n";
    cout << "                (hex: " << toHex(decrypted, decLen) << ")\n\n";

    cout << "Проверка тега:  " << (ok ? "успешно" : "ОШИБКА!") << "\n";
    cout << "Совпадение с исходным текстом: " << (decMsg == msg ? "да" : "нет") << "\n";

    return 0;
}

