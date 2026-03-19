// secure_copy.cpp
// Многопоточное копирование с шифрованием нескольких файлов
// Использует libcaesar.so

#include <iostream>
#include <fstream>
#include <string>
#include <queue>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <errno.h>

#define _GNU_SOURCE

// Размер блока для чтения/записи
const size_t BLOCK_SIZE = 4096;
// Количество рабочих потоков
const int NUM_THREADS = 3;

// Флаг для сигнала
volatile sig_atomic_t keep_running = 1;

// Очередь задач
struct Task {
    std::string inPath;
    std::string outPath;
};

std::queue<Task> taskQueue;
pthread_mutex_t queueMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queueCond = PTHREAD_COND_INITIALIZER;

// Мьютекс для логирования
pthread_mutex_t logMutex = PTHREAD_MUTEX_INITIALIZER;

// Функции из библиотеки libcaesar
extern "C" {
    void set_key(char key);
    void caesar(void* src, void* dst, int len);
}

// Получение системного идентификатора потока
pid_t gettid() {
    return static_cast<pid_t>(syscall(SYS_gettid));
}

// Обработчик сигнала SIGINT
void sigint_handler(int) {
    keep_running = 0;
    // Разбудим ожидающие потоки (не обязательно, но полезно)
    pthread_cond_broadcast(&queueCond);
}

// Функция обработки одного файла
void processFile(const std::string& inPath, const std::string& outPath) {
    std::ifstream inFile(inPath, std::ios::binary);
    if (!inFile) {
        std::cerr << "Ошибка: не удалось открыть входной файл " << inPath << std::endl;
        return;
    }

    // Создаем выходной файл, предварительно создавая директорию? Директория уже создана в main.
    std::ofstream outFile(outPath, std::ios::binary);
    if (!outFile) {
        std::cerr << "Ошибка: не удалось создать выходной файл " << outPath << std::endl;
        return;
    }

    char buffer[BLOCK_SIZE];
    bool success = true;

    while (keep_running) {
        inFile.read(buffer, BLOCK_SIZE);
        std::streamsize bytesRead = inFile.gcount();
        if (bytesRead == 0) break;

        // Шифрование
        caesar(buffer, buffer, static_cast<int>(bytesRead));

        outFile.write(buffer, bytesRead);
        if (!outFile) {
            std::cerr << "Ошибка записи в файл " << outPath << std::endl;
            success = false;
            break;
        }
    }

    inFile.close();
    outFile.close();

    // Если операция была прервана, не логируем
    if (!keep_running) {
        std::cerr << "Операция прервана во время обработки файла " << inPath << std::endl;
        return;
    }

    if (!success) return;

    // Логирование успешной обработки
    pthread_mutex_lock(&logMutex);
    std::ofstream logFile("log.txt", std::ios::app);
    if (logFile) {
        time_t now = time(nullptr);
        struct tm* tm_info = localtime(&now);
        char timeBuf[20];
        strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", tm_info);
        pid_t pid = getpid();
        pid_t tid = gettid();
        logFile << timeBuf << " PID:" << pid << " TID:" << tid << " " << inPath << std::endl;
        logFile.close();
    } else {
        std::cerr << "Ошибка открытия файла лога" << std::endl;
    }
    pthread_mutex_unlock(&logMutex);
}

// Рабочая функция потока
void* worker(void*) {
    while (keep_running) {
        // Захват мьютекса очереди с таймаутом 5 секунд
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        int rc = pthread_mutex_timedlock(&queueMutex, &ts);
        if (rc == ETIMEDOUT) {
            std::cerr << "Deadlock: не удалось захватить мьютекс очереди в течение 5 секунд. Завершение." << std::endl;
            exit(1);
        } else if (rc != 0) {
            std::cerr << "Ошибка захвата мьютекса: " << rc << std::endl;
            exit(1);
        }

        // Ожидание появления задач с периодической проверкой keep_running
        while (taskQueue.empty() && keep_running) {
            struct timespec wait_ts;
            clock_gettime(CLOCK_REALTIME, &wait_ts);
            wait_ts.tv_sec += 1; // ждем 1 секунду
            pthread_cond_timedwait(&queueCond, &queueMutex, &wait_ts);
        }

        if (!keep_running) {
            pthread_mutex_unlock(&queueMutex);
            break;
        }

        // Извлекаем задачу
        Task task = taskQueue.front();
        taskQueue.pop();
        pthread_mutex_unlock(&queueMutex);

        // Если это маркер завершения, выходим
        if (task.inPath.empty()) {
            break;
        }

        // Обрабатываем файл
        processFile(task.inPath, task.outPath);
    }
    return nullptr;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Использование: " << argv[0] << " <file1> [file2 ...] <out_dir> <key>" << std::endl;
        return 1;
    }

    // Извлекаем аргументы
    std::string outDir = argv[argc - 2];
    char* endptr;
    long keyLong = strtol(argv[argc - 1], &endptr, 10);
    if (*endptr != '\0' || keyLong < 0 || keyLong > 255) {
        std::cerr << "Ошибка: ключ должен быть целым числом от 0 до 255" << std::endl;
        return 1;
    }
    unsigned char key = static_cast<unsigned char>(keyLong);

    // Создаем выходную директорию, если её нет
    if (mkdir(outDir.c_str(), 0777) != 0 && errno != EEXIST) {
        std::cerr << "Ошибка создания директории " << outDir << std::endl;
        return 1;
    }

    // Устанавливаем обработчик сигнала
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, nullptr) == -1) {
        std::cerr << "Ошибка установки обработчика сигнала" << std::endl;
        return 1;
    }

    // Устанавливаем ключ шифрования (один для всех)
    set_key(static_cast<char>(key));

    // Формируем задачи для всех входных файлов
    int numFiles = argc - 3;
    for (int i = 1; i <= numFiles; ++i) {
        std::string inPath = argv[i];
        // Извлекаем имя файла без пути
        size_t pos = inPath.find_last_of("/\\");
        std::string filename = (pos == std::string::npos) ? inPath : inPath.substr(pos + 1);
        std::string outPath = outDir + "/" + filename;

        Task task;
        task.inPath = inPath;
        task.outPath = outPath;

        pthread_mutex_lock(&queueMutex);
        taskQueue.push(task);
        pthread_cond_signal(&queueCond);
        pthread_mutex_unlock(&queueMutex);
    }

    // Создаем рабочие потоки
    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; ++i) {
        if (pthread_create(&threads[i], nullptr, worker, nullptr) != 0) {
            std::cerr << "Ошибка создания потока " << i << std::endl;
            // Завершаем уже созданные потоки
            for (int j = 0; j < i; ++j) {
                pthread_cancel(threads[j]); // не лучший способ, но для простоты
                pthread_join(threads[j], nullptr);
            }
            return 1;
        }
    }

    // Добавляем маркеры завершения (по одному на поток)
    for (int i = 0; i < NUM_THREADS; ++i) {
        Task stopTask;
        stopTask.inPath = ""; // пустой путь означает маркер
        pthread_mutex_lock(&queueMutex);
        taskQueue.push(stopTask);
        pthread_cond_signal(&queueCond);
        pthread_mutex_unlock(&queueMutex);
    }

    // Ожидаем завершения всех потоков
    for (int i = 0; i < NUM_THREADS; ++i) {
        pthread_join(threads[i], nullptr);
    }

    if (!keep_running) {
        std::cout << "Операция прервана пользователем" << std::endl;
    }

    // Очистка ресурсов (необязательно, т.к. программа завершается)
    pthread_mutex_destroy(&queueMutex);
    pthread_cond_destroy(&queueCond);
    pthread_mutex_destroy(&logMutex);

    return 0;
}