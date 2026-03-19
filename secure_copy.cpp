#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>

const size_t BLOCK_SIZE = 4096;
const int NUM_WORKERS = 3;

// Функции из библиотеки libcaesar
extern "C" {
    void set_key(char key);
    void caesar(void* src, void* dst, int len);
}

// Глобальный флаг для сигнала
volatile sig_atomic_t keep_running = 1;

// Очередь задач (файлы для обработки)
struct TaskQueue {
    std::vector<std::string> files;
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    TaskQueue() {
        pthread_mutex_init(&mutex, nullptr);
        pthread_cond_init(&cond, nullptr);
    }

    ~TaskQueue() {
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
    }
};

// Аргументы для рабочих потоков
struct WorkerArgs {
    TaskQueue* queue;
    std::string outDir;
    unsigned char key;
    std::vector<std::string>* failedFiles; // список файлов, которые не удалось обработать
    pthread_mutex_t* failedMutex;          // мьютекс для доступа к failedFiles
};

// Обработчик SIGINT
void sigint_handler(int) {
    keep_running = 0;
}

// Функция для обработки одного файла (чтение, шифрование, запись)
void processFile(const std::string& filename, const std::string& outDir, unsigned char key, std::vector<std::string>* failedFiles, pthread_mutex_t* failedMutex) {
    std::string outPath = outDir + "/" + filename.substr(filename.find_last_of("/\\") + 1);

    std::ifstream inFile(filename, std::ios::binary);
    if (!inFile) {
        pthread_mutex_lock(failedMutex);
        failedFiles->push_back(filename);
        pthread_mutex_unlock(failedMutex);
        std::cerr << "Error opening input file: " << filename << std::endl;
        return;
    }

    std::ofstream outFile(outPath, std::ios::binary);
    if (!outFile) {
        inFile.close();
        pthread_mutex_lock(failedMutex);
        failedFiles->push_back(filename);
        pthread_mutex_unlock(failedMutex);
        std::cerr << "Error opening output file: " << outPath << std::endl;
        return;
    }

    set_key(static_cast<char>(key));

    char buffer[BLOCK_SIZE];
    while (keep_running && inFile) {
        inFile.read(buffer, BLOCK_SIZE);
        std::streamsize bytesRead = inFile.gcount();
        if (bytesRead > 0) {
            // Шифрование на месте
            caesar(buffer, buffer, static_cast<int>(bytesRead));
            outFile.write(buffer, bytesRead);
        }
    }

    inFile.close();
    outFile.close();

    // Логирование успешной обработки
    if (keep_running) {
        time_t now = time(nullptr);
        struct tm* tm_info = localtime(&now);
        char timeBuf[20];
        strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", tm_info);

        pthread_t tid = pthread_self();
        std::ofstream logFile("log.txt", std::ios::app);
        if (logFile) {
            logFile << timeBuf << " PID:" << getpid() << " TID:" << tid << " " << filename << std::endl;
        }
    }
}

// Рабочий поток
void* workerThread(void* arg) {
    WorkerArgs* args = static_cast<WorkerArgs*>(arg);
    TaskQueue* queue = args->queue;
    std::string outDir = args->outDir;
    unsigned char key = args->key;
    auto failedFiles = args->failedFiles;
    auto failedMutex = args->failedMutex;

    while (keep_running) {
        // Пытаемся захватить мьютекс очереди через trylock
        int lockRet = pthread_mutex_trylock(&queue->mutex);
        if (lockRet == 0) {
            // Успешно: берём задание
            if (queue->files.empty()) {
                pthread_mutex_unlock(&queue->mutex);
                break;
            }
            std::string filename = queue->files.back();
            queue->files.pop_back();
            pthread_mutex_unlock(&queue->mutex);

            processFile(filename, outDir, key, failedFiles, failedMutex);
        }
        else if (lockRet == EBUSY) {
            // Мьютекс занят, ждём с таймаутом 5 секунд
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 5;

            int timedRet = pthread_mutex_timedlock(&queue->mutex, &ts);
            if (timedRet == 0) {
                if (queue->files.empty()) {
                    pthread_mutex_unlock(&queue->mutex);
                    break;
                }
                std::string filename = queue->files.back();
                queue->files.pop_back();
                pthread_mutex_unlock(&queue->mutex);

                processFile(filename, outDir, key, failedFiles, failedMutex);
            }
            else if (timedRet == ETIMEDOUT) {
                std::cerr << "Cannot acquire queue mutex within 5 seconds – possible deadlock. Exiting." << std::endl;
                exit(1);
            }
            else {
                std::cerr << "Mutex timedlock error: " << timedRet << std::endl;
                exit(1);
            }
        }
        else {
            std::cerr << "Mutex trylock error: " << lockRet << std::endl;
            exit(1);
        }
    }
    return nullptr;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <file1> [file2] ... [fileN] <out_dir> <key>" << std::endl;
        return 1;
    }

    // Последний аргумент — ключ, предпоследний — выходная папка
    char* endptr;
    long keyLong = strtol(argv[argc-1], &endptr, 10);
    if (*endptr != '\0' || keyLong < 0 || keyLong > 255) {
        std::cerr << "Error: key must be integer 0-255" << std::endl;
        return 1;
    }
    unsigned char key = static_cast<unsigned char>(keyLong);

    std::string outDir = argv[argc-2];

    // Создаём выходную папку, если её нет
    struct stat st;
    if (stat(outDir.c_str(), &st) != 0) {
        if (mkdir(outDir.c_str(), 0755) != 0) {
            std::cerr << "Error creating output directory: " << outDir << std::endl;
            return 1;
        }
    } else if (!S_ISDIR(st.st_mode)) {
        std::cerr << "Error: " << outDir << " is not a directory" << std::endl;
        return 1;
    }

    // Собираем список входных файлов
    std::vector<std::string> inputFiles;
    for (int i = 1; i < argc-2; ++i) {
        inputFiles.push_back(argv[i]);
    }

    // Устанавливаем обработчик SIGINT
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, nullptr) == -1) {
        std::cerr << "Error setting signal handler" << std::endl;
        return 1;
    }

    // Инициализация очереди задач
    TaskQueue queue;
    for (const auto& f : inputFiles) {
        queue.files.push_back(f);
    }

    // Мьютекс для списка неудачных файлов
    pthread_mutex_t failedMutex;
    pthread_mutex_init(&failedMutex, nullptr);
    std::vector<std::string> failedFiles;

    // Запуск рабочих потоков
    pthread_t workers[NUM_WORKERS];
    WorkerArgs args[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; ++i) {
        args[i].queue = &queue;
        args[i].outDir = outDir;
        args[i].key = key;
        args[i].failedFiles = &failedFiles;
        args[i].failedMutex = &failedMutex;
        if (pthread_create(&workers[i], nullptr, workerThread, &args[i]) != 0) {
            std::cerr << "Error creating worker thread" << std::endl;
            // Завершаем уже созданные потоки
            for (int j = 0; j < i; ++j) {
                pthread_cancel(workers[j]);
                pthread_join(workers[j], nullptr);
            }
            pthread_mutex_destroy(&failedMutex);
            return 1;
        }
    }

    // Ожидание завершения всех потоков
    for (int i = 0; i < NUM_WORKERS; ++i) {
        pthread_join(workers[i], nullptr);
    }

    pthread_mutex_destroy(&failedMutex);

    // Вывод информации о неудачных файлах
    if (!failedFiles.empty()) {
        std::cerr << "The following files could not be processed:" << std::endl;
        for (const auto& f : failedFiles) {
            std::cerr << "  " << f << std::endl;
        }
    }

    if (!keep_running) {
        std::cout << "Operation interrupted by user" << std::endl;
    }

    return 0;
}