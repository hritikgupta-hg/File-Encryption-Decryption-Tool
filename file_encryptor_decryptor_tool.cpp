#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>

class EncryptionAlgorithm {
public:
    virtual std::string encrypt(const std::string& input, int key) const = 0;
    virtual std::string decrypt(const std::string& input, int key) const = 0;
    virtual ~EncryptionAlgorithm() = default;
};

class CaesarCipher : public EncryptionAlgorithm {
public:
    std::string encrypt(const std::string& input, int key) const override {
        return applyCaesarCipher(input, key);
    }

    std::string decrypt(const std::string& input, int key) const override {
        return applyCaesarCipher(input, -key);
    }

private:
    std::string applyCaesarCipher(const std::string& input, int key) const {
        std::string result = input;
        for (char& ch : result) {
            if (isalpha(ch)) {
                char base = isupper(ch) ? 'A' : 'a';
                ch = static_cast<char>((ch - base + key + 26) % 26 + base);
            }
        }
        return result;
    }
};

class AtbashCipher : public EncryptionAlgorithm {
public:
    std::string encrypt(const std::string& input, int key) const override {
        return applyAtbashCipher(input);
    }

    std::string decrypt(const std::string& input, int key) const override {
        // Decryption for Atbash cipher is the same as encryption
        return applyAtbashCipher(input);
    }

private:
    std::string applyAtbashCipher(const std::string& input) const {
        std::string result = input;
        for (char& ch : result) {
            if (isalpha(ch)) {
                char base = isupper(ch) ? 'A' : 'a';
                ch = static_cast<char>(25 - (ch - base) + base);
            }
        }
        return result;
    }
};

class FileEncryptor {
public:
    FileEncryptor(const std::string& fileName) : fileName(fileName) {}

    void encrypt(int key, const EncryptionAlgorithm& algorithm) {
        std::string content = readFile();
        std::string encryptedContent = algorithm.encrypt(content, key);
        writeFile(encryptedContent, getOutputFileName("encrypted"));
        std::cout << "Encryption complete. Encrypted file: " << getOutputFileName("encrypted") << std::endl;
    }

    void decrypt(int key, const EncryptionAlgorithm& algorithm) {
        std::string content = readFile(getOutputFileName("encrypted"));
        std::string decryptedContent = algorithm.decrypt(content, key);
        writeFile(decryptedContent, getOutputFileName("decrypted"));
        std::cout << "Decryption complete. Decrypted file: " << getOutputFileName("decrypted") << std::endl;
    }

private:
    std::string fileName;

    std::string readFile(const std::string& specificFileName = "") const {
        std::ifstream file(specificFileName.empty() ? fileName : specificFileName);
        std::string content;

        if (file.is_open()) {
            char ch;
            while (file.get(ch)) {
                content.push_back(ch);
            }
            file.close();
        } else {
            std::cerr << "Error: Unable to open file " << fileName << std::endl;
        }

        return content;
    }

    void writeFile(const std::string& content, const std::string& specificFileName) const {
        std::ofstream file(specificFileName);
        if (file.is_open()) {
            file << content;
            file.close();
        } else {
            std::cerr << "Error: Unable to create file " << specificFileName << std::endl;
        }
    }

    std::string getOutputFileName(const std::string& operation) const {
        size_t dotPos = fileName.find_last_of('.');
        if (dotPos != std::string::npos) {
            return fileName.substr(0, dotPos) + "_" + operation + fileName.substr(dotPos);
        } else {
            return fileName + "_" + operation;
        }
    }
};

int main() {
    std::string fileName;
    int key;
    int algorithmChoice;

    std::cout << "Enter the name of the file to encrypt/decrypt: ";
    std::cin >> fileName;

    std::cout << "Enter the key for encryption/decryption: ";
    std::cin >> key;

    std::cout << "Select encryption algorithm:\n";
    std::cout << "1. Caesar Cipher\n";
    std::cout << "2. Atbash Cipher\n";
    std::cout << "Enter your choice: ";
    std::cin >> algorithmChoice;

    EncryptionAlgorithm* selectedAlgorithm;
    switch (algorithmChoice) {
        case 1:
            selectedAlgorithm = new CaesarCipher();
            break;
        case 2:
            selectedAlgorithm = new AtbashCipher();
            break;
        default:
            std::cerr << "Invalid choice. Exiting program.\n";
            return 1;
    }

    FileEncryptor encryptor(fileName);
    // encryptor.encrypt(key, *selectedAlgorithm);
    encryptor.decrypt(key, *selectedAlgorithm);

    delete selectedAlgorithm; // Don't forget to release memory

    return 0;
}
