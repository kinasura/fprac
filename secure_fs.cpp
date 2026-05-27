/**
 * Secure File Storage with RC4 Stream Encryption
 * 
 * This program implements a protected file storage in a single disk image file.
 * Each file is encrypted with RC4 using a seed derived from:
 * - Master key (provided by user via -key)
 * - Random 16-byte salt (unique per file, stored in the image)
 * 
 * Image format (sequential records):
 * [Record1][Record2][Record3]...
 * 
 * Record structure:
 * - uint32_t encrypted_data_size (4 bytes, little-endian) - size m of encrypted content
 * - uint32_t name_size (4 bytes, little-endian) - length n of filename in bytes (no null terminator)
 * - uint8_t salt[16] (16 bytes) - random salt unique for each file
 * - char filename[name_size] (n bytes) - UTF-8 relative path from image root
 * - uint8_t encrypted_data[m] (m bytes) - RC4 encrypted file content
 * 
 * Seed for RC4 = master_key + salt (concatenation in that order)
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <random>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <functional>
#include <atomic>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <cstdlib>

// ============================================================================
// RC4 Stream Cipher Implementation (standalone, no external libraries)
// ============================================================================

class RC4 {
private:
    uint8_t S[256];  // State array (permutation)
    uint8_t i, j;    // Indices

public:
    RC4() : i(0), j(0) {
        memset(S, 0, sizeof(S));
    }

    /**
     * Initialize RC4 state using Key-Scheduling Algorithm (KSA)
     * @param key Pointer to key bytes (seed = master_key + salt)
     * @param key_len Length of the key in bytes (1-256)
     */
    void init(const uint8_t* key, size_t key_len) {
        if (key_len == 0 || key_len > 256) {
            return;
        }

        // Initialize S box with identity permutation
        for (int idx = 0; idx < 256; idx++) {
            S[idx] = static_cast<uint8_t>(idx);
        }

        // Key-scheduling algorithm (KSA)
        uint8_t j_temp = 0;
        for (int idx = 0; idx < 256; idx++) {
            j_temp = (j_temp + S[idx] + key[idx % key_len]) % 256;
            std::swap(S[idx], S[j_temp]);
        }

        // Reset indices for PRGA
        i = 0;
        j = 0;
    }

    /**
     * Generate next byte of keystream and XOR with input byte
     * Pseudo-Random Generation Algorithm (PRGA)
     */
    uint8_t process(uint8_t byte) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        
        uint8_t K = S[(S[i] + S[j]) % 256];
        return byte ^ K;
    }

    /**
     * Encrypt/decrypt a buffer in-place
     * @param buffer Pointer to data buffer
     * @param len Length of buffer in bytes
     */
    void process_buffer(uint8_t* buffer, size_t len) {
        for (size_t idx = 0; idx < len; idx++) {
            buffer[idx] = process(buffer[idx]);
        }
    }
};

// ============================================================================
// Thread Pool Implementation (max 5 threads)
// ============================================================================

class ThreadPool {
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    std::atomic<bool> stop{false};

public:
    ThreadPool(size_t num_threads) {
        for (size_t i = 0; i < num_threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        condition.wait(lock, [this] { 
                            return stop.load() || !tasks.empty(); 
                        });
                        if (stop.load() && tasks.empty()) {
                            return;
                        }
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
        }
    }

    template<class F>
    void enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }

    ~ThreadPool() {
        stop.store(true);
        condition.notify_all();
        for (std::thread& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }
};

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
    if (!is) {
        throw std::runtime_error("Failed to read uint32");
    }
    return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

/**
 * Get relative path from base directory
 */
std::string get_relative_path(const std::string& base_dir, const std::string& full_path) {
    if (full_path.size() <= base_dir.size()) {
        return full_path;
    }
    std::string rel = full_path.substr(base_dir.size());
    if (!rel.empty() && rel[0] == '/') {
        rel = rel.substr(1);
    }
    return rel;
}

/**
 * Recursively collect all files from a directory
 */
void collect_files(const std::string& path, std::vector<std::string>& files, 
                   const std::string& base_dir, const std::string& rel_prefix) {
    DIR* dir = opendir(path.c_str());
    if (!dir) {
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") {
            continue;
        }

        std::string full_path = path + "/" + name;
        std::string rel_path = rel_prefix.empty() ? name : rel_prefix + "/" + name;

        struct stat st;
        if (stat(full_path.c_str(), &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            collect_files(full_path, files, base_dir, rel_path);
        } else if (S_ISREG(st.st_mode)) {
            files.push_back(rel_path);
        }
    }
    closedir(dir);
}

// ============================================================================
// Secure Image Class
// ============================================================================

class SecureImage {
private:
    std::string image_path;
    std::string master_key;
    std::mutex write_mutex;

    static constexpr size_t BUFFER_SIZE = 4096;

    /**
     * Create RC4 seed from master key and salt
     * Seed = master_key + salt (concatenation)
     */
    std::vector<uint8_t> create_seed(const uint8_t* salt, size_t salt_len) {
        std::vector<uint8_t> seed(master_key.size() + salt_len);
        std::memcpy(seed.data(), master_key.c_str(), master_key.size());
        std::memcpy(seed.data() + master_key.size(), salt, salt_len);
        return seed;
    }

public:
    SecureImage(const std::string& path, const std::string& key)
        : image_path(path), master_key(key) {}

    /**
     * Add a single file to the image (thread-safe)
     * @param rel_path Relative path of the file within the image
     * @param base_dir Base directory for resolving the actual file path
     */
    bool add_file_threadsafe(const std::string& rel_path, const std::string& base_dir) {
        std::string full_path = base_dir + "/" + rel_path;
        
        // Check if source file exists and get its size
        std::ifstream src(full_path, std::ios::binary | std::ios::ate);
        if (!src) {
            std::cerr << "Error: Cannot open source file: " << full_path << std::endl;
            return false;
        }

        size_t file_size = src.tellg();
        src.seekg(0, std::ios::beg);

        // Generate random salt (16 bytes)
        uint8_t salt[16];
        generate_salt(salt, 16);

        // Create seed for RC4: master_key + salt
        std::vector<uint8_t> seed = create_seed(salt, 16);

        // Open image for appending (with mutex for thread safety)
        std::lock_guard<std::mutex> lock(write_mutex);
        
        std::ofstream image(image_path, std::ios::binary | std::ios::app);
        if (!image) {
            std::cerr << "Error: Cannot open/create image: " << image_path << std::endl;
            return false;
        }

        // Get image end position
        image.seekp(0, std::ios::end);

        // Write header
        uint32_t name_size = static_cast<uint32_t>(rel_path.size());
        write_uint32(image, static_cast<uint32_t>(file_size));
        write_uint32(image, name_size);
        image.write(reinterpret_cast<char*>(salt), 16);
        image.write(rel_path.c_str(), name_size);

        // Encrypt and write data using RC4
        RC4 rc4;
        rc4.init(seed.data(), seed.size());

        std::vector<uint8_t> buffer(BUFFER_SIZE);
        size_t remaining = file_size;

        while (remaining > 0) {
            size_t to_read = std::min(BUFFER_SIZE, remaining);
            src.read(reinterpret_cast<char*>(buffer.data()), to_read);
            size_t bytes_read = src.gcount();

            if (bytes_read == 0) break;

            rc4.process_buffer(buffer.data(), bytes_read);
            image.write(reinterpret_cast<char*>(buffer.data()), bytes_read);

            remaining -= bytes_read;
        }

        image.close();
        src.close();

        std::cout << "Added: " << rel_path << " (" << file_size << " bytes)" << std::endl;
        return true;
    }

    /**
     * Add multiple files using a thread pool (max 5 threads)
     */
    bool add_files_parallel(const std::vector<std::string>& files, const std::string& base_dir) {
        ThreadPool pool(5);  // Maximum 5 threads as per specification
        std::atomic<int> success_count{0};
        std::atomic<int> fail_count{0};

        for (const auto& rel_path : files) {
            pool.enqueue([this, &rel_path, &base_dir, &success_count, &fail_count] {
                if (add_file_threadsafe(rel_path, base_dir)) {
                    success_count++;
                } else {
                    fail_count++;
                }
            });
        }

        // Wait for all tasks to complete (pool destructor joins all threads)
        // But we need to ensure the pool stays alive until all tasks are done
        // The destructor will handle this
        
        return fail_count.load() == 0;
    }

    /**
     * List all files in the image (sorted lexicographically)
     */
    bool list_files() {
        std::ifstream image(image_path, std::ios::binary);
        if (!image) {
            std::cerr << "Error: Cannot open image: " << image_path << std::endl;
            return false;
        }

        // Get image size for bounds checking
        image.seekg(0, std::ios::end);
        std::streampos image_size = image.tellg();
        image.seekg(0, std::ios::beg);

        std::vector<std::pair<std::string, uint32_t>> entries;
        const size_t HEADER_BASE_SIZE = 24; // 4 + 4 + 16 bytes

        while (image.peek() != EOF) {
            std::streampos current_pos = image.tellg();
            
            // Check if we have enough bytes for base header
            if (static_cast<size_t>(image_size - current_pos) < HEADER_BASE_SIZE) {
                break;
            }

            try {
                uint32_t data_size = read_uint32(image);
                uint32_t name_size = read_uint32(image);

                // Validate name_size
                if (name_size == 0 || name_size > 10 * 1024 * 1024) {
                    break;
                }

                // Check if we have enough bytes for salt and filename
                if (static_cast<size_t>(image_size - image.tellg()) < 16 + name_size) {
                    break;
                }

                uint8_t salt[16];
                image.read(reinterpret_cast<char*>(salt), 16);

                std::vector<char> filename(name_size);
                image.read(filename.data(), name_size);

                if (!image) {
                    break;
                }

                std::string name(filename.data(), name_size);
                entries.emplace_back(name, data_size);

                // Skip encrypted data
                if (static_cast<size_t>(image_size - image.tellg()) < data_size) {
                    break;
                }
                image.seekg(data_size, std::ios::cur);

            } catch (...) {
                break;
            }
        }

        image.close();

        // Sort entries lexicographically by filename
        std::sort(entries.begin(), entries.end(), 
                  [](const auto& a, const auto& b) { return a.first < b.first; });

        // Output sorted list
        for (const auto& entry : entries) {
            std::cout << entry.first << "\t" << entry.second << std::endl;
        }

        if (entries.empty()) {
            std::cout << "(empty image)" << std::endl;
        }

        return true;
    }

    /**
     * Extract a file from the image
     */
    bool extract_file(const std::string& target_name, const std::string& output_path) {
        std::ifstream image(image_path, std::ios::binary);
        if (!image) {
            std::cerr << "Error: Cannot open image: " << image_path << std::endl;
            return false;
        }

        image.seekg(0, std::ios::end);
        std::streampos image_size = image.tellg();
        image.seekg(0, std::ios::beg);

        bool found = false;
        const size_t HEADER_BASE_SIZE = 24;

        while (image.peek() != EOF && !found) {
            std::streampos record_start = image.tellg();

            if (static_cast<size_t>(image_size - record_start) < HEADER_BASE_SIZE) {
                break;
            }

            try {
                uint32_t data_size = read_uint32(image);
                uint32_t name_size = read_uint32(image);

                if (name_size == 0 || name_size > 10 * 1024 * 1024) {
                    break;
                }

                if (static_cast<size_t>(image_size - image.tellg()) < 16 + name_size) {
                    break;
                }

                uint8_t salt[16];
                image.read(reinterpret_cast<char*>(salt), 16);

                std::vector<char> filename(name_size);
                image.read(filename.data(), name_size);

                if (!image) {
                    break;
                }

                std::string name(filename.data(), name_size);

                if (name == target_name) {
                    found = true;

                    if (static_cast<size_t>(image_size - image.tellg()) < data_size) {
                        std::cerr << "Error: Data exceeds image bounds" << std::endl;
                        return false;
                    }

                    // Create seed for RC4 decryption
                    std::vector<uint8_t> seed = create_seed(salt, 16);

                    // Open output file
                    std::ofstream output(output_path, std::ios::binary);
                    if (!output) {
                        std::cerr << "Error: Cannot create output file: " << output_path << std::endl;
                        return false;
                    }

                    // Initialize RC4 with fresh state
                    RC4 rc4;
                    rc4.init(seed.data(), seed.size());

                    // Decrypt and write data
                    std::vector<uint8_t> buffer(BUFFER_SIZE);
                    size_t remaining = data_size;

                    while (remaining > 0) {
                        size_t to_read = std::min(BUFFER_SIZE, remaining);
                        image.read(reinterpret_cast<char*>(buffer.data()), to_read);
                        size_t bytes_read = image.gcount();

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
                    if (static_cast<size_t>(image_size - image.tellg()) < data_size) {
                        break;
                    }
                    image.seekg(data_size, std::ios::cur);
                }

            } catch (...) {
                break;
            }
        }

        image.close();

        if (!found) {
            std::cerr << "Error: File not found in image: " << target_name << std::endl;
            return false;
        }

        return true;
    }
};
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

        // Get container size for bounds checking
        container.seekg(0, std::ios::end);
        std::streampos container_size = container.tellg();
        container.seekg(0, std::ios::beg);

        bool found_any = false;
        const size_t HEADER_BASE_SIZE = 24; // 4 + 4 + 16 bytes

        while (container.peek() != EOF) {
            // Check if we have enough bytes for base header
            std::streampos current_pos = container.tellg();
            if (static_cast<size_t>(container_size - current_pos) < HEADER_BASE_SIZE) {
                std::cerr << "Warning: Incomplete header at position " << current_pos 
                          << " (only " << (container_size - current_pos) << " bytes remaining)" << std::endl;
                break;
            }

            // Read header
            uint32_t data_size = read_uint32(container);
            uint32_t name_size = read_uint32(container);

            // Validate name_size to prevent reading beyond bounds
            if (name_size == 0 || name_size > 1024) {
                std::cerr << "Warning: Invalid name_size (" << name_size 
                          << ") at position " << current_pos << std::endl;
                break;
            }

            // Check if we have enough bytes for salt and filename
            if (static_cast<size_t>(container_size - container.tellg()) < 16 + name_size) {
                std::cerr << "Warning: Record exceeds container bounds at position " 
                          << current_pos << std::endl;
                break;
            }

            uint8_t salt[16];
            container.read(reinterpret_cast<char*>(salt), 16);

            std::vector<char> filename(name_size);
            container.read(filename.data(), name_size);

            if (!container) {
                std::cerr << "Error: Corrupted container format" << std::endl;
                return false;
            }

            // Ensure null-termination for safety
            if (filename.back() != '\0') {
                filename.push_back('\0');
            }

            std::cout << filename.data() << " (" << data_size << " bytes)" << std::endl;
            found_any = true;

            // Check if data extends beyond container
            if (static_cast<size_t>(container_size - container.tellg()) < data_size) {
                std::cerr << "Warning: Data exceeds container bounds for file \"" 
                          << filename.data() << "\"" << std::endl;
                break;
            }

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

        // Get container size for bounds checking
        container.seekg(0, std::ios::end);
        std::streampos container_size = container.tellg();
        container.seekg(0, std::ios::beg);

        bool found = false;
        const size_t HEADER_BASE_SIZE = 24; // 4 + 4 + 16 bytes

        while (container.peek() != EOF && !found) {
            // Remember position at start of record
            std::streampos record_start = container.tellg();

            // Check if we have enough bytes for base header
            if (static_cast<size_t>(container_size - record_start) < HEADER_BASE_SIZE) {
                std::cerr << "Warning: Incomplete header at position " << record_start << std::endl;
                break;
            }

            // Read header
            uint32_t data_size = read_uint32(container);
            uint32_t name_size = read_uint32(container);

            // Validate name_size
            if (name_size == 0 || name_size > 1024) {
                std::cerr << "Warning: Invalid name_size (" << name_size 
                          << ") at position " << record_start << std::endl;
                break;
            }

            // Check if we have enough bytes for salt and filename
            if (static_cast<size_t>(container_size - container.tellg()) < 16 + name_size) {
                std::cerr << "Warning: Record exceeds container bounds at position " 
                          << record_start << std::endl;
                break;
            }

            uint8_t salt[16];
            container.read(reinterpret_cast<char*>(salt), 16);

            std::vector<char> filename(name_size);
            container.read(filename.data(), name_size);

            if (!container) {
                std::cerr << "Error: Corrupted container format" << std::endl;
                return false;
            }

            // Ensure null-termination for safety
            if (filename.back() != '\0') {
                filename.push_back('\0');
            }

            // Check if this is the target file
            if (std::string(filename.data()) == target_name) {
                found = true;

                // Check if data extends beyond container
                if (static_cast<size_t>(container_size - container.tellg()) < data_size) {
                    std::cerr << "Error: Data exceeds container bounds for file \"" 
                              << filename.data() << "\"" << std::endl;
                    return false;
                }

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
                // Check bounds before skipping
                if (static_cast<size_t>(container_size - container.tellg()) < data_size) {
                    std::cerr << "Warning: Data exceeds container bounds while searching for \"" 
                              << target_name << "\"" << std::endl;
                    break;
                }
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
