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
#include <algorithm>
#include <iomanip>

// Константы
const size_t BLOCK_SIZE = 4096;
const int WORKERS_COUNT = 4;          // Максимум параллельных потоков
const int AUTO_THRESHOLD = 5;         // При количестве файлов >=5 выбираем parallel

// Функции из библиотеки libcaesar
extern "C" {
    void set_key(char key);
    void caesar(void* src, void* dst, int len);
}

// Глобальный флаг для сигнала (Ctrl+C)
volatile sig_atomic_t keep_running = 1;

// Структура для хранения статистики обработки
struct ProcessStats {
    double total_time_ms;      // общее время выполнения (мс)
    double avg_time_per_file_ms; // среднее время на файл (мс)
    int files_processed;       // количество обработанных файлов
};

// Очередь задач для параллельного режима (потокобезопасная)
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

// Аргументы для рабочих потоков (параллельный режим)
struct WorkerArgs {
    TaskQueue* queue;
    std::string outDir;
    unsigned char key;
    std::vector<std::string>* failedFiles;
    pthread_mutex_t* failedMutex;
};

// Обработчик сигнала SIGINT
void sigint_handler(int) {
    keep_running = 0;
}

// Функция обработки одного файла (чтение, шифрование, запись)
// Возвращает true в случае успеха, false – при ошибке
bool processFile(const std::string& filename, const std::string& outDir, unsigned char key) {
    // Формируем путь выходного файла
    std::string outPath = outDir + "/" + filename.substr(filename.find_last_of("/\\") + 1);

    std::ifstream inFile(filename, std::ios::binary);
    if (!inFile) {
        std::cerr << "Ошибка открытия входного файла: " << filename << std::endl;
        return false;
    }

    std::ofstream outFile(outPath, std::ios::binary);
    if (!outFile) {
        inFile.close();
        std::cerr << "Ошибка открытия выходного файла: " << outPath << std::endl;
        return false;
    }

    set_key(static_cast<char>(key));

    char buffer[BLOCK_SIZE];
    while (keep_running && inFile) {
        inFile.read(buffer, BLOCK_SIZE);
        std::streamsize bytesRead = inFile.gcount();
        if (bytesRead > 0) {
            caesar(buffer, buffer, static_cast<int>(bytesRead));
            outFile.write(buffer, bytesRead);
        }
    }

    inFile.close();
    outFile.close();

    return keep_running; // true, если не было прерывания
}

// Рабочий поток для параллельного режима
void* workerThread(void* arg) {
    WorkerArgs* args = static_cast<WorkerArgs*>(arg);
    TaskQueue* queue = args->queue;
    std::string outDir = args->outDir;
    unsigned char key = args->key;
    auto failedFiles = args->failedFiles;
    auto failedMutex = args->failedMutex;

    while (keep_running) {
        // Захватываем мьютекс очереди (сначала trylock, потом timedlock)
        int lockRet = pthread_mutex_trylock(&queue->mutex);
        if (lockRet == 0) {
            // Мьютекс захвачен – берём задание
            if (queue->files.empty()) {
                pthread_mutex_unlock(&queue->mutex);
                break; // очередь пуста, поток завершается
            }
            std::string filename = queue->files.back();
            queue->files.pop_back();
            pthread_mutex_unlock(&queue->mutex);

            // Обрабатываем файл
            bool success = processFile(filename, outDir, key);
            if (!success && keep_running) {
                pthread_mutex_lock(failedMutex);
                failedFiles->push_back(filename);
                pthread_mutex_unlock(failedMutex);
            }
        }
        else if (lockRet == EBUSY) {
            // Мьютекс занят – ждём с таймаутом 5 секунд
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

                bool success = processFile(filename, outDir, key);
                if (!success && keep_running) {
                    pthread_mutex_lock(failedMutex);
                    failedFiles->push_back(filename);
                    pthread_mutex_unlock(failedMutex);
                }
            }
            else if (timedRet == ETIMEDOUT) {
                std::cerr << "Не удалось захватить мьютекс очереди за 5 секунд – возможная взаимоблокировка. Завершение." << std::endl;
                exit(1);
            }
            else {
                std::cerr << "Ошибка timedlock: " << timedRet << std::endl;
                exit(1);
            }
        }
        else {
            std::cerr << "Ошибка trylock: " << lockRet << std::endl;
            exit(1);
        }
    }
    return nullptr;
}

// Последовательный режим
ProcessStats runSequential(const std::vector<std::string>& inputFiles, const std::string& outDir, unsigned char key) {
    ProcessStats stats = { 0.0, 0.0, 0 };
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (const auto& filename : inputFiles) {
        if (!keep_running) break;
        bool success = processFile(filename, outDir, key);
        if (success) stats.files_processed++;
        else if (keep_running) {
            std::cerr << "Ошибка обработки файла: " << filename << std::endl;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    stats.total_time_ms = (end.tv_sec - start.tv_sec) * 1000.0 +
        (end.tv_nsec - start.tv_nsec) / 1000000.0;
    if (stats.files_processed > 0)
        stats.avg_time_per_file_ms = stats.total_time_ms / stats.files_processed;

    return stats;
}

// Параллельный режим
ProcessStats runParallel(const std::vector<std::string>& inputFiles, const std::string& outDir, unsigned char key) {
    ProcessStats stats = { 0.0, 0.0, 0 };
    struct timespec start, end;

    // Создаём очередь задач
    TaskQueue queue;
    queue.files = inputFiles; // копируем список файлов

    // Мьютекс для списка неудачных файлов
    pthread_mutex_t failedMutex;
    pthread_mutex_init(&failedMutex, nullptr);
    std::vector<std::string> failedFiles;

    // Запускаем рабочие потоки
    pthread_t workers[WORKERS_COUNT];
    WorkerArgs args[WORKERS_COUNT];
    for (int i = 0; i < WORKERS_COUNT; ++i) {
        args[i].queue = &queue;
        args[i].outDir = outDir;
        args[i].key = key;
        args[i].failedFiles = &failedFiles;
        args[i].failedMutex = &failedMutex;
        if (pthread_create(&workers[i], nullptr, workerThread, &args[i]) != 0) {
            std::cerr << "Ошибка создания рабочего потока" << std::endl;
            // Завершаем уже созданные потоки
            for (int j = 0; j < i; ++j) {
                pthread_cancel(workers[j]);
                pthread_join(workers[j], nullptr);
            }
            pthread_mutex_destroy(&failedMutex);
            return stats;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &start);

    // Ожидаем завершения всех потоков
    for (int i = 0; i < WORKERS_COUNT; ++i) {
        pthread_join(workers[i], nullptr);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    // Подсчитываем успешно обработанные файлы
    stats.files_processed = inputFiles.size() - failedFiles.size();
    stats.total_time_ms = (end.tv_sec - start.tv_sec) * 1000.0 +
        (end.tv_nsec - start.tv_nsec) / 1000000.0;
    if (stats.files_processed > 0)
        stats.avg_time_per_file_ms = stats.total_time_ms / stats.files_processed;

    pthread_mutex_destroy(&failedMutex);

    // Выводим список неудачных файлов (если есть)
    if (!failedFiles.empty()) {
        std::cerr << "Следующие файлы не были обработаны:" << std::endl;
        for (const auto& f : failedFiles) std::cerr << "  " << f << std::endl;
    }

    return stats;
}

// Вспомогательная функция для создания директории
bool createDirectory(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        if (S_ISDIR(st.st_mode)) return true;
        else return false;
    }
    return (mkdir(path.c_str(), 0755) == 0);
}

// Вывод статистики
void printStats(const std::string& modeName, const ProcessStats& stats) {
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Режим: " << modeName << std::endl;
    std::cout << "  Обработано файлов: " << stats.files_processed << std::endl;
    std::cout << "  Общее время: " << stats.total_time_ms << " мс" << std::endl;
    std::cout << "  Среднее время на файл: " << stats.avg_time_per_file_ms << " мс" << std::endl;
}

int main(int argc, char* argv[]) {
    // --- Парсинг аргументов командной строки ---
    std::string modeArg = "auto"; // по умолчанию auto
    std::vector<std::string> inputFiles;
    std::string outDir;
    unsigned char key = 0;

    // Сначала ищем аргумент --mode=...
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.find("--mode=") == 0) {
            modeArg = arg.substr(7);
            break;
        }
    }

    // Собираем остальные аргументы (игнорируя --mode)
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.find("--mode=") == 0) continue;

        if (inputFiles.empty() && (arg == "sequential" || arg == "parallel" || arg == "auto")) {
            // старый формат без --mode=, поддержим для совместимости
            modeArg = arg;
            continue;
        }
        inputFiles.push_back(arg);
    }

    // Проверяем минимальное количество аргументов: файлы (хотя бы 1) + папка + ключ
    if (inputFiles.size() < 3) {
        std::cerr << "Использование: " << argv[0] << " [--mode=sequential|parallel|auto] <файл1> [файл2] ... <выходная_папка> <ключ>" << std::endl;
        std::cerr << "  --mode=auto (по умолчанию) выбирает режим автоматически (<5 файлов -> sequential, >=5 -> parallel)" << std::endl;
        return 1;
    }

    // Последний аргумент — ключ, предпоследний — выходная папка
    char* endptr;
    long keyLong = strtol(inputFiles.back().c_str(), &endptr, 10);
    if (*endptr != '\0' || keyLong < 0 || keyLong > 255) {
        std::cerr << "Ошибка: ключ должен быть целым числом от 0 до 255" << std::endl;
        return 1;
    }
    key = static_cast<unsigned char>(keyLong);
    inputFiles.pop_back();

    outDir = inputFiles.back();
    inputFiles.pop_back();

    if (inputFiles.empty()) {
        std::cerr << "Ошибка: не указано ни одного входного файла" << std::endl;
        return 1;
    }

    // Создаём выходную директорию, если её нет
    if (!createDirectory(outDir)) {
        std::cerr << "Ошибка: не удалось создать директорию " << outDir << std::endl;
        return 1;
    }

    // --- Определение режимов ---
    bool isAuto = (modeArg == "auto");
    bool useSequential = false, useParallel = false;

    if (isAuto) {
        int fileCount = inputFiles.size();
        if (fileCount < AUTO_THRESHOLD) {
            useSequential = true;
            useParallel = false;
            std::cout << "Автоматический выбор: последовательный режим (файлов: " << fileCount << " < " << AUTO_THRESHOLD << ")" << std::endl;
        }
        else {
            useSequential = false;
            useParallel = true;
            std::cout << "Автоматический выбор: параллельный режим (файлов: " << fileCount << " >= " << AUTO_THRESHOLD << ")" << std::endl;
        }
    }
    else if (modeArg == "sequential") {
        useSequential = true;
    }
    else if (modeArg == "parallel") {
        useParallel = true;
    }
    else {
        std::cerr << "Ошибка: неизвестный режим '" << modeArg << "'. Используйте sequential, parallel или auto" << std::endl;
        return 1;
    }

    // --- Установка обработчика сигнала ---
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, nullptr) == -1) {
        std::cerr << "Ошибка установки обработчика сигнала" << std::endl;
        return 1;
    }

    // --- Запуск выбранного режима ---
    ProcessStats selectedStats;
    if (useSequential) {
        selectedStats = runSequential(inputFiles, outDir, key);
    }
    else if (useParallel) {
        selectedStats = runParallel(inputFiles, outDir, key);
    }

    // Если была прервана по Ctrl+C, выводим сообщение
    if (!keep_running) {
        std::cout << "Операция прервана пользователем" << std::endl;
        return 0;
    }

    // --- В автоматическом режиме выводим сравнение с альтернативным режимом ---
    if (isAuto) {
        std::cout << "\n=== Сравнительная таблица ===" << std::endl;
        printStats(useSequential ? "Последовательный (выбранный)" : "Параллельный (выбранный)", selectedStats);

        // Запускаем альтернативный режим в отдельную временную папку
        std::string altOutDir = outDir + "_alt";
        if (createDirectory(altOutDir)) {
            ProcessStats altStats;
            if (useSequential) {
                altStats = runParallel(inputFiles, altOutDir, key);
                printStats("Параллельный (альтернативный)", altStats);
            }
            else {
                altStats = runSequential(inputFiles, altOutDir, key);
                printStats("Последовательный (альтернативный)", altStats);
            }
            // Удаляем временную папку (опционально)
            // rmdir(altOutDir.c_str()); // для простоты не удаляем рекурсивно
        }
        else {
            std::cerr << "Не удалось создать временную папку для сравнения" << std::endl;
        }
    }
    else {
        std::cout << "\n=== Результаты работы ===" << std::endl;
        printStats(useSequential ? "Последовательный" : "Параллельный", selectedStats);
    }

    return 0;
}