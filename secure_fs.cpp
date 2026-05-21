/**
 * Secure File Container with RC4 Stream Encryption
 * 
 * This program implements a protected file storage in a single container file.
 * Each file is encrypted with RC4 using a unique key derived from:
 * - Global password (provided by user)
 * - Random 16-byte salt (unique per file)
 * 
 * Container format:
 * [Header][Encrypted Data][Header][Encrypted Data]...
 * 
 * Header structure:
 * - uint32_t data_size (4 bytes, little-endian)
 * - uint32_t name_size (4 bytes, little-endian)
 * - uint8_t salt[16] (16 bytes)
 * - char filename[name_size] (variable length)
 */

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <random>
#include <openssl/sha.h>
#include <unistd.h>
#include <sys/stat.h>

// ============================================================================
// RC4 Stream Cipher Implementation
// ============================================================================

class RC4 {
private:
    uint8_t S[256];  // State array
    uint8_t i, j;    // Indices

public:
    RC4() : i(0), j(0) {}

    /**
     * Initialize RC4 with a key of arbitrary length (1-256 bytes)
     */
    void init(const uint8_t* key, size_t key_len) {
        // Key-scheduling algorithm (KSA)
        for (int idx = 0; idx < 256; idx++) {
            S[idx] = static_cast<uint8_t>(idx);
        }

        uint8_t j_temp = 0;
        for (int idx = 0; idx < 256; idx++) {
            j_temp = (j_temp + S[idx] + key[idx % key_len]) % 256;
            std::swap(S[idx], S[j_temp]);
        }

        i = 0;
        j = 0;
    }

    /**
     * Encrypt/decrypt a single byte (XOR with keystream)
     */
    uint8_t process(uint8_t byte) {
        // Pseudo-random generation algorithm (PRGA)
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        
        uint8_t K = S[(S[i] + S[j]) % 256];
        return byte ^ K;
    }

    /**
     * Encrypt/decrypt a buffer in-place
     */
    void process_buffer(uint8_t* buffer, size_t len) {
        for (size_t idx = 0; idx < len; idx++) {
            buffer[idx] = process(buffer[idx]);
        }
    }
};

// ============================================================================
// Record Header Structure
// ============================================================================

#pragma pack(push, 1)
struct RecordHeader {
    uint32_t data_size;   // Size of encrypted data
    uint32_t name_size;   // Length of filename (including null terminator)
    uint8_t salt[16];     // Random salt for key derivation
    // Followed by: char filename[name_size]
};
#pragma pack(pop)

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generate random bytes using /dev/urandom
 */
void generate_salt(uint8_t* salt, size_t len) {
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom || !urandom.read(reinterpret_cast<char*>(salt), len)) {
        // Fallback to random device
        std::random_device rd;
        for (size_t idx = 0; idx < len; idx++) {
            salt[idx] = static_cast<uint8_t>(rd() & 0xFF);
        }
    }
}

/**
 * Compute SHA-256 hash of data
 * Returns 32-byte hash
 */
std::vector<uint8_t> sha256(const uint8_t* data, size_t len) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data, len, hash.data());
    return hash;
}

/**
 * Derive RC4 key from global password and salt
 * RC4 key = SHA-256(password || salt)
 */
std::vector<uint8_t> derive_key(const std::string& password, const uint8_t* salt, size_t salt_len) {
    std::vector<uint8_t> combined(password.size() + salt_len);
    std::memcpy(combined.data(), password.c_str(), password.size());
    std::memcpy(combined.data() + password.size(), salt, salt_len);
    return sha256(combined.data(), combined.size());
}

/**
 * Write uint32 in little-endian format
 */
void write_uint32(std::ostream& os, uint32_t value) {
    uint8_t buf[4];
    buf[0] = value & 0xFF;
    buf[1] = (value >> 8) & 0xFF;
    buf[2] = (value >> 16) & 0xFF;
    buf[3] = (value >> 24) & 0xFF;
    os.write(reinterpret_cast<char*>(buf), 4);
}

/**
 * Read uint32 in little-endian format
 */
uint32_t read_uint32(std::istream& is) {
    uint8_t buf[4];
    is.read(reinterpret_cast<char*>(buf), 4);
    return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

// ============================================================================
// Secure Container Class
// ============================================================================

class SecureContainer {
private:
    std::string container_path;
    std::string password;

    static constexpr size_t BUFFER_SIZE = 4096;

public:
    SecureContainer(const std::string& path, const std::string& pass)
        : container_path(path), password(pass) {}

    /**
     * Add a file to the container
     */
    bool add_file(const std::string& filename) {
        // Check if source file exists and get its size
        std::ifstream src(filename, std::ios::binary | std::ios::ate);
        if (!src) {
            std::cerr << "Error: Cannot open source file: " << filename << std::endl;
            return false;
        }

        size_t file_size = src.tellg();
        src.seekg(0, std::ios::beg);

        // Generate random salt
        uint8_t salt[16];
        generate_salt(salt, 16);

        // Derive RC4 key
        std::vector<uint8_t> rc4_key = derive_key(password, salt, 16);

        // Open container for appending
        std::ofstream container(container_path, std::ios::binary | std::ios::app);
        if (!container) {
            std::cerr << "Error: Cannot open/create container: " << container_path << std::endl;
            return false;
        }

        // Prepare header
        std::string name_with_path = filename;
        uint32_t name_size = static_cast<uint32_t>(name_with_path.size() + 1); // Include null terminator

        // Write header
        write_uint32(container, static_cast<uint32_t>(file_size));
        write_uint32(container, name_size);
        container.write(reinterpret_cast<char*>(salt), 16);
        container.write(name_with_path.c_str(), name_size);

        // Encrypt and write data
        RC4 rc4;
        rc4.init(rc4_key.data(), rc4_key.size());

        std::vector<uint8_t> buffer(BUFFER_SIZE);
        size_t remaining = file_size;

        while (remaining > 0) {
            size_t to_read = std::min(BUFFER_SIZE, remaining);
            src.read(reinterpret_cast<char*>(buffer.data()), to_read);
            size_t bytes_read = src.gcount();

            if (bytes_read == 0) break;

            rc4.process_buffer(buffer.data(), bytes_read);
            container.write(reinterpret_cast<char*>(buffer.data()), bytes_read);

            remaining -= bytes_read;
        }

        container.close();
        src.close();

        std::cout << "Added: " << filename << " (" << file_size << " bytes)" << std::endl;
        return true;
    }

    /**
     * List all files in the container
     */
    bool list_files() {
        std::ifstream container(container_path, std::ios::binary);
        if (!container) {
            std::cerr << "Error: Cannot open container: " << container_path << std::endl;
            return false;
        }

        bool found_any = false;

        while (container.peek() != EOF) {
            // Read header
            uint32_t data_size = read_uint32(container);
            uint32_t name_size = read_uint32(container);

            uint8_t salt[16];
            container.read(reinterpret_cast<char*>(salt), 16);

            std::vector<char> filename(name_size);
            container.read(filename.data(), name_size);

            if (!container) {
                std::cerr << "Error: Corrupted container format" << std::endl;
                return false;
            }

            std::cout << filename.data() << " (" << data_size << " bytes)" << std::endl;
            found_any = true;

            // Skip encrypted data
            container.seekg(data_size, std::ios::cur);
        }

        container.close();

        if (!found_any) {
            std::cout << "(empty container)" << std::endl;
        }

        return true;
    }

    /**
     * Extract a file from the container
     */
    bool extract_file(const std::string& target_name, const std::string& output_path) {
        std::ifstream container(container_path, std::ios::binary);
        if (!container) {
            std::cerr << "Error: Cannot open container: " << container_path << std::endl;
            return false;
        }

        bool found = false;

        while (container.peek() != EOF && !found) {
            // Remember position at start of record
            std::streampos record_start = container.tellg();

            // Read header
            uint32_t data_size = read_uint32(container);
            uint32_t name_size = read_uint32(container);

            uint8_t salt[16];
            container.read(reinterpret_cast<char*>(salt), 16);

            std::vector<char> filename(name_size);
            container.read(filename.data(), name_size);

            if (!container) {
                std::cerr << "Error: Corrupted container format" << std::endl;
                return false;
            }

            // Check if this is the target file
            if (filename.data() == target_name) {
                found = true;

                // Derive RC4 key
                std::vector<uint8_t> rc4_key = derive_key(password, salt, 16);

                // Open output file
                std::ofstream output(output_path, std::ios::binary);
                if (!output) {
                    std::cerr << "Error: Cannot create output file: " << output_path << std::endl;
                    return false;
                }

                // Initialize RC4 with fresh context
                RC4 rc4;
                rc4.init(rc4_key.data(), rc4_key.size());

                // Decrypt and write data
                std::vector<uint8_t> buffer(BUFFER_SIZE);
                size_t remaining = data_size;

                while (remaining > 0) {
                    size_t to_read = std::min(BUFFER_SIZE, remaining);
                    container.read(reinterpret_cast<char*>(buffer.data()), to_read);
                    size_t bytes_read = container.gcount();

                    if (bytes_read == 0) break;

                    rc4.process_buffer(buffer.data(), bytes_read);
                    output.write(reinterpret_cast<char*>(buffer.data()), bytes_read);

                    remaining -= bytes_read;
                }

                output.close();
                std::cout << "Extracted: " << target_name << " -> " << output_path 
                          << " (" << data_size << " bytes)" << std::endl;
            } else {
                // Skip encrypted data
                container.seekg(data_size, std::ios::cur);
            }
        }

        container.close();

        if (!found) {
            std::cerr << "Error: File not found in container: " << target_name << std::endl;
            return false;
        }

        return true;
    }
};

// ============================================================================
// Command Line Interface
// ============================================================================

void print_usage(const char* prog_name) {
    std::cerr << "Usage:" << std::endl;
    std::cerr << "  " << prog_name << " --key=<password> add <container> <file>" << std::endl;
    std::cerr << "  " << prog_name << " --key=<password> list <container>" << std::endl;
    std::cerr << "  " << prog_name << " --key=<password> extract <container> <filename> [output]" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Options:" << std::endl;
    std::cerr << "  --key=<password>   Global encryption password (required)" << std::endl;
    std::cerr << "  --help             Show this help message" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string password;
    std::string mode;
    std::vector<std::string> args;

    // Parse arguments
    for (int idx = 1; idx < argc; idx++) {
        std::string arg = argv[idx];

        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg.rfind("--key=", 0) == 0) {
            password = arg.substr(6);
        } else if (arg.rfind("--key", 0) == 0 && arg[5] == '=') {
            password = arg.substr(6);
        } else if (mode.empty() && (arg == "add" || arg == "list" || arg == "extract")) {
            mode = arg;
        } else {
            args.push_back(arg);
        }
    }

    // Check for password in environment if not provided
    if (password.empty()) {
        const char* env_pass = std::getenv("SECURE_FS_KEY");
        if (env_pass) {
            password = env_pass;
        }
    }

    if (password.empty()) {
        std::cerr << "Error: Password required. Use --key=<password> or set SECURE_FS_KEY environment variable." << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    if (mode.empty()) {
        std::cerr << "Error: Mode required (add, list, extract)" << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    // Execute mode
    SecureContainer container("", password);

    if (mode == "add") {
        if (args.size() < 2) {
            std::cerr << "Error: add requires <container> and <file> arguments" << std::endl;
            return 1;
        }
        container = SecureContainer(args[0], password);
        if (!container.add_file(args[1])) {
            return 1;
        }

    } else if (mode == "list") {
        if (args.empty()) {
            std::cerr << "Error: list requires <container> argument" << std::endl;
            return 1;
        }
        container = SecureContainer(args[0], password);
        if (!container.list_files()) {
            return 1;
        }

    } else if (mode == "extract") {
        if (args.size() < 2) {
            std::cerr << "Error: extract requires <container> and <filename> arguments" << std::endl;
            return 1;
        }
        container = SecureContainer(args[0], password);
        std::string output = (args.size() >= 3) ? args[2] : args[1];
        
        // Extract just the filename from path if output equals input filename
        if (output == args[1]) {
            size_t pos = args[1].rfind('/');
            if (pos != std::string::npos) {
                output = args[1].substr(pos + 1);
            }
        }
        
        if (!container.extract_file(args[1], output)) {
            return 1;
        }

    } else {
        std::cerr << "Error: Unknown mode: " << mode << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
