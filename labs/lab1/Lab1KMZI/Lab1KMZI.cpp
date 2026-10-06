#include <iostream>
#include <iomanip>
#include <sstream>
#include "Calculator.h"
#include "Belt.h"
#include "BeltGcm.h"
using namespace std;

static string toHex(const vector<uint8_t>& d) {
    ostringstream ss;
    for (auto b : d) ss << hex << setw(2) << setfill('0') << (int)b;
    return ss.str();
}

int main() {
    setlocale(LC_ALL, "Russian");

    Calculator calc;
    cout << "Сложение:  " << hex << (int)calc.gf_add(0x57, 0x83) << "\n";
    cout << "Умножение: " << hex << (int)calc.gf_mul(0x57, 0x83) << "\n";
    cout << "Инверсия:  " << hex << (int)calc.gf_inv(0x57) << dec << "\n\n";

    Belt belt;
    vector<uint8_t> keyBytes = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                 0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F };
    auto key = belt.keyExpand(keyBytes);

    BeltGcm gcm(key);
    vector<uint8_t> iv = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B };

    string msg = "Secret message";
    vector<uint8_t> plaintext(msg.begin(), msg.end());
    vector<uint8_t> aad = { 'h','d','r' };

    cout << "Открытый текст: " << msg << "\n";
    cout << "                (hex: " << toHex(plaintext) << ")\n\n";

    auto enc = gcm.encrypt(iv, plaintext, aad);
    cout << "Зашифровано:    " << toHex(enc.ciphertext) << "\n";
    cout << "Тег аутентификации: " << toHex(vector<uint8_t>(enc.tag.begin(), enc.tag.end())) << "\n\n";

    vector<uint8_t> decrypted;
    bool ok = gcm.decrypt(iv, enc.ciphertext, aad, enc.tag, decrypted);
    string decMsg(decrypted.begin(), decrypted.end());

    cout << "Расшифровано:   " << decMsg << "\n";
    cout << "                (hex: " << toHex(decrypted) << ")\n\n";

    cout << "Проверка тега:  " << (ok ? "успешно" : "ОШИБКА!") << "\n";
    cout << "Совпадение с исходным текстом: " << (decMsg == msg ? "да" : "нет") << "\n";

    return 0;
}

