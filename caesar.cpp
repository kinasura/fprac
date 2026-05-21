#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static void* key_page = nullptr;   // указатель на выделенную страницу
static size_t page_size = 0;        // размер системной страницы

// Инициализация: выделяет страницу с правами RW
static int init_key_storage() {
    if (key_page != nullptr) return 0; // уже инициализировано
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return -1;
    // Выделяем анонимную страницу (не связана с файлом)
    key_page = mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (key_page == MAP_FAILED) return -1;
    // Заполняем нулями (безопасно, т.к. права RW есть)
    memset(key_page, 0, page_size);
    // (Опционально) заблокировать страницу в ОЗУ, чтобы не ушла в swap
    // mlock(key_page, page_size);   // требуется CAP_IPC_LOCK или sudo
    return 0;
}

// Освобождение страницы с затиранием
static void destroy_key_storage() {
    if (key_page == nullptr) return;
    // Снимаем блокировку, если была
    // munlock(key_page, page_size);
    // Временно даём права на запись для затирания
    mprotect(key_page, page_size, PROT_READ | PROT_WRITE);
    // Затираем всю страницу нулями (используем volatile, чтобы оптимизатор не удалил)
    volatile char* p = static_cast<volatile char*>(key_page);
    for (size_t i = 0; i < page_size; ++i) p[i] = 0;
    // Освобождаем память
    munmap(key_page, page_size);
    key_page = nullptr;
}

extern "C" {

    // Установить ключ
    void set_key(char key) {
        if (init_key_storage() != 0) return;
        // На время записи даём права на запись (если уже были только чтение)
        mprotect(key_page, page_size, PROT_READ | PROT_WRITE);
        *(static_cast<char*>(key_page)) = key;
        // Возвращаем защиту только на чтение
        mprotect(key_page, page_size, PROT_READ);
    }

    // Получить текущий ключ (вспомогательная функция, необязательна)
    char get_key() {
        if (key_page == nullptr) return 0;
        // Страница доступна на чтение, можно просто прочитать
        return *(static_cast<char*>(key_page));
    }

    // Шифрование/дешифрование
    void caesar(void* src, void* dst, int len) {
        char key = 0;
        if (key_page != nullptr) {
            key = *(static_cast<char*>(key_page));
        }
        // Если ключ не был установлен (key_page == nullptr), key=0 -> XOR не меняет данные
        char* s = static_cast<char*>(src);
        char* d = static_cast<char*>(dst);
        for (int i = 0; i < len; ++i) {
            d[i] = s[i] ^ key;
        }
    }

    // Функция, которая автоматически вызовется при выгрузке библиотеки (dlclose или exit)
    void __attribute__((destructor)) cleanup_lib() {
        destroy_key_storage();
    }
}