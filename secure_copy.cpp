// secure_copy.cpp
#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <pthread.h>

// Размер блока данных
const size_t BLOCK_SIZE = 4096;
// Размер очереди (количество блоков)
const size_t QUEUE_SIZE = 10;

// Структура блока данных
struct DataBlock {
    char data[BLOCK_SIZE];
    size_t size;      // реальный размер (может быть меньше BLOCK_SIZE для последнего блока)
};

// Глобальный флаг для сигнала (должен быть перед классом, который его использует)
volatile sig_atomic_t keep_running = 1;

// Очередь с ограниченным размером (кольцевой буфер)
class BlockingQueue {
public:
    BlockingQueue(size_t maxSize) : maxSize(maxSize), head(0), tail(0), count(0) {
        buffer = new DataBlock*[maxSize];
        pthread_mutex_init(&mutex, nullptr);
        pthread_cond_init(&condNotEmpty, nullptr);
        pthread_cond_init(&condNotFull, nullptr);
    }

    ~BlockingQueue() {
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&condNotEmpty);
        pthread_cond_destroy(&condNotFull);
        delete[] buffer;
    }

    void push(DataBlock* block) {
        pthread_mutex_lock(&mutex);
        while (count >= maxSize && keep_running) {
            pthread_cond_wait(&condNotFull, &mutex);
        }
        if (!keep_running) {
            pthread_mutex_unlock(&mutex);
            return;
        }
        buffer[tail] = block;
        tail = (tail + 1) % maxSize;
        count++;
        pthread_cond_signal(&condNotEmpty);
        pthread_mutex_unlock(&mutex);
    }

    DataBlock* pop() {
        pthread_mutex_lock(&mutex);
        while (count == 0 && keep_running) {
            pthread_cond_wait(&condNotEmpty, &mutex);
        }
        if (!keep_running) {
            pthread_mutex_unlock(&mutex);
            return nullptr;
        }
        DataBlock* block = buffer[head];
        head = (head + 1) % maxSize;
        count--;
        pthread_cond_signal(&condNotFull);
        pthread_mutex_unlock(&mutex);
        return block;
    }

private:
    DataBlock** buffer;
    size_t maxSize;
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t mutex;
    pthread_cond_t condNotEmpty;
    pthread_cond_t condNotFull;
};

// Обработчик SIGINT
void sigint_handler(int) {
    keep_running = 0;
}

// Структура для передачи аргументов в потоки
struct ThreadArgs {
    std::string inputFile;
    std::string outputFile;
    unsigned char key;
    BlockingQueue* queue;
};

// Объявление функций из библиотеки libcaesar
extern "C" {
    void set_key(char key);
    void caesar(void* src, void* dst, int len);
}

// Поток-производитель
void* producerThread(void* arg) {
    ThreadArgs* args = static_cast<ThreadArgs*>(arg);
    std::ifstream inFile(args->inputFile, std::ios::binary);
    if (!inFile) {
        std::cerr << "Ошибка: не удалось открыть входной файл " << args->inputFile << std::endl;
        keep_running = 0;
        return nullptr;
    }

    set_key(static_cast<char>(args->key));

    while (keep_running) {
        DataBlock* block = new DataBlock;
        inFile.read(block->data, BLOCK_SIZE);
        block->size = inFile.gcount();

        if (block->size == 0) {
            delete block;
            break;
        }

        // Шифрование на месте
        caesar(block->data, block->data, static_cast<int>(block->size));

        args->queue->push(block);

        if (inFile.eof()) break;
    }

    // Маркер конца
    DataBlock* endBlock = new DataBlock;
    endBlock->size = 0;
    args->queue->push(endBlock);

    inFile.close();
    return nullptr;
}

// Поток-потребитель
void* consumerThread(void* arg) {
    ThreadArgs* args = static_cast<ThreadArgs*>(arg);
    std::ofstream outFile(args->outputFile, std::ios::binary);
    if (!outFile) {
        std::cerr << "Ошибка: не удалось открыть выходной файл " << args->outputFile << std::endl;
        keep_running = 0;
        return nullptr;
    }

    while (keep_running) {
        DataBlock* block = args->queue->pop();
        if (!block) break;

        if (block->size == 0) {
            delete block;
            break;
        }

        outFile.write(block->data, block->size);
        delete block;
    }

    outFile.close();
    return nullptr;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Использование: " << argv[0] << " <входной_файл> <выходной_файл> <ключ>" << std::endl;
        return 1;
    }

    std::string inputFile = argv[1];
    std::string outputFile = argv[2];
    char* endptr;
    long keyLong = strtol(argv[3], &endptr, 10);
    if (*endptr != '\0' || keyLong < 0 || keyLong > 255) {
        std::cerr << "Ошибка: ключ должен быть целым числом от 0 до 255" << std::endl;
        return 1;
    }
    unsigned char key = static_cast<unsigned char>(keyLong);

    // Установка обработчика SIGINT
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, nullptr) == -1) {
        std::cerr << "Ошибка установки обработчика сигнала" << std::endl;
        return 1;
    }

    BlockingQueue queue(QUEUE_SIZE);
    ThreadArgs args = {inputFile, outputFile, key, &queue};

    pthread_t producer, consumer;
    if (pthread_create(&producer, nullptr, producerThread, &args) != 0) {
        std::cerr << "Ошибка создания потока-производителя" << std::endl;
        return 1;
    }
    if (pthread_create(&consumer, nullptr, consumerThread, &args) != 0) {
        std::cerr << "Ошибка создания потока-потребителя" << std::endl;
        pthread_cancel(producer);
        pthread_join(producer, nullptr);
        return 1;
    }

    pthread_join(producer, nullptr);
    pthread_join(consumer, nullptr);

    if (!keep_running) {
        std::cout << "Операция прервана пользователем" << std::endl;
    }

    return 0;
}