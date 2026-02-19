#!/usr/bin/env python3
import sys
import ctypes

def main():
    if len(sys.argv) != 5:
        print("Использование: test_caesar.py <путь_к_библиотеке> <ключ> <входной_файл> <выходной_файл>")
        sys.exit(1)

    lib_path = sys.argv[1]
    key_arg = sys.argv[2]
    input_file = sys.argv[3]
    output_file = sys.argv[4]

    try:
        key = int(key_arg) & 0xFF
    except ValueError:
        if len(key_arg) > 0:
            key = ord(key_arg[0])
        else:
            key = 0

    try:
        lib = ctypes.CDLL(lib_path)
    except Exception as e:
        print(f"Ошибка загрузки библиотеки: {e}")
        sys.exit(1)

    lib.set_key.argtypes = [ctypes.c_char]
    lib.caesar.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]

    lib.set_key(bytes([key]))

    with open(input_file, 'rb') as f:
        data = f.read()
    length = len(data)

    src = (ctypes.c_char * length).from_buffer_copy(data)
    dst = (ctypes.c_char * length)()

    lib.caesar(ctypes.addressof(src), ctypes.addressof(dst), length)

    with open(output_file, 'wb') as f:
        f.write(bytearray(dst))

if __name__ == "__main__":
    main()