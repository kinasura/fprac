#include <iostream>
#include <dlfcn.h>


int main() {
    void* lib = dlopen("./libcaesar.so", RTLD_LAZY);
    auto set_key = (void(*)(char)) dlsym(lib, "set_key");
    auto caesar = (void(*)(void*,void*,int)) dlsym(lib, "caesar");

    set_key(42);
    // Попытка изменить ключ через указатель на страницу – невозможно,
    // т.к. библиотека не экспортирует key_page. Но если бы мы нашли адрес,
    // запись вызвала бы SIGSEGV.

    char data = 'A', out;
    caesar(&data, &out, 1);
    std::cout << "Encrypted: " << (int)out << std::endl; // 'A' ^ 42 = 107

    dlclose(lib);
    return 0;
}