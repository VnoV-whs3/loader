#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <iomanip>  // std::setfill, std::setw를 위해 추가
#include <algorithm> // std::min을 위해 추가

using namespace std; // 네임스페이스 추가

class SimpleCrypto {
private:
    vector<BYTE> key = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    vector<BYTE> iv = { 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89 };

public:
    // 암호화 함수 (복호화와 동일한 XOR 연산)
    vector<BYTE> Encrypt(const vector<BYTE>& plainData) {
        vector<BYTE> encrypted = plainData;
        for (size_t i = 0; i < encrypted.size(); i++) {
            encrypted[i] ^= key[i % key.size()];
            encrypted[i] ^= iv[i % iv.size()];
        }
        return encrypted;
    }

    // 복호화 함수 (확인용)
    vector<BYTE> Decrypt(const vector<BYTE>& encryptedData) {
        vector<BYTE> decrypted = encryptedData;
        for (size_t i = 0; i < decrypted.size(); i++) {
            decrypted[i] ^= key[i % key.size()];
            decrypted[i] ^= iv[i % iv.size()];
        }
        return decrypted;
    }
};

class FileEncryptor {
private:
    SimpleCrypto crypto;

    vector<BYTE> LoadFile(const string& filename) {
        ifstream file(filename, ios::binary);
        if (!file.is_open()) {
            cout << "Failed to open file: " << filename << endl;
            return {};
        }

        vector<BYTE> data((istreambuf_iterator<char>(file)),
            istreambuf_iterator<char>());
        file.close();

        return data;
    }

    bool SaveFile(const string& filename, const vector<BYTE>& data) {
        ofstream file(filename, ios::binary);
        if (!file.is_open()) {
            cout << "Failed to create file: " << filename << endl;
            return false;
        }

        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        file.close();

        return true;
    }

    void PrintHexDump(const vector<BYTE>& data, const string& title, size_t maxBytes = 32) {
        cout << title << " (first " << maxBytes << " bytes):" << endl;
        size_t dumpSize = min(data.size(), maxBytes);

        for (size_t i = 0; i < dumpSize; i++) {
            if (i % 16 == 0) {
                cout << hex << setfill('0') << setw(8) << i << ": ";
            }
            cout << hex << setfill('0') << setw(2) <<
                static_cast<unsigned int>(data[i]) << " ";
            if ((i + 1) % 16 == 0) {
                cout << endl;
            }
        }
        if (dumpSize % 16 != 0) {
            cout << endl;
        }
        cout << endl;
    }

    bool ValidatePEFile(const vector<BYTE>& data) {
        if (data.size() < sizeof(IMAGE_DOS_HEADER)) {
            return false;
        }

        const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            cout << "Warning: Not a valid PE file (DOS signature: 0x" <<
                hex << dosHeader->e_magic << ")" << endl;
            return false;
        }

        cout << "Valid PE file detected (DOS signature: MZ)" << endl;
        return true;
    }

public:
    bool EncryptFile(const string& inputPath, const string& outputPath) {
        cout << "=== PE File Encryptor ===" << endl;
        cout << "Input file: " << inputPath << endl;
        cout << "Output file: " << outputPath << endl << endl;

        // 원본 파일 로드
        cout << "Loading original file..." << endl;
        vector<BYTE> originalData = LoadFile(inputPath);
        if (originalData.empty()) {
            return false;
        }

        cout << "Original file size: " << originalData.size() << " bytes" << endl;

        // PE 파일 검증
        ValidatePEFile(originalData);
        PrintHexDump(originalData, "Original file");

        // 암호화
        cout << "Encrypting file..." << endl;
        vector<BYTE> encryptedData = crypto.Encrypt(originalData);

        cout << "Encrypted file size: " << encryptedData.size() << " bytes" << endl;
        PrintHexDump(encryptedData, "Encrypted file");

        // 암호화된 파일 저장
        cout << "Saving encrypted file..." << endl;
        if (!SaveFile(outputPath, encryptedData)) {
            return false;
        }

        // 검증: 복호화 테스트
        cout << "Verifying encryption..." << endl;
        vector<BYTE> decryptedData = crypto.Decrypt(encryptedData);

        if (decryptedData.size() == originalData.size() &&
            memcmp(decryptedData.data(), originalData.data(), originalData.size()) == 0) {
            cout << "✓ Encryption verification successful!" << endl;
            PrintHexDump(decryptedData, "Decrypted verification");
        }
        else {
            cout << "✗ Encryption verification failed!" << endl;
            return false;
        }

        return true;
    }
};

int main() {
    try {
        FileEncryptor encryptor;

        string inputPath, outputPath;

        cout << "Enter path to mimikatz.exe (or any PE file): ";
        getline(cin, inputPath);

        cout << "Enter output path for encrypted file: ";
        getline(cin, outputPath);

        if (encryptor.EncryptFile(inputPath, outputPath)) {
            cout << "\n=== SUCCESS ===" << endl;
            cout << "File encrypted successfully!" << endl;
            cout << "You can now use '" << outputPath << "' with your PE loader." << endl;
        }
        else {
            cout << "\n=== FAILED ===" << endl;
            cout << "File encryption failed!" << endl;
        }

        cout << "\nPress Enter to exit...";
        cin.get();

    }
    catch (const exception& e) {
        cout << "Exception: " << e.what() << endl;
    }

    return 0;
}
