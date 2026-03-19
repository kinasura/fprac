CC = g++
CFLAGS = -Wall -pthread
TARGET = secure_copy
LIB = libcaesar.so

all: $(TARGET)

$(TARGET): secure_copy.cpp $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -L. -lcaesar

testfile:
	dd if=/dev/urandom of=test10M.bin bs=1M count=10

test_secure: $(TARGET) testfile
	@echo "Шифрование test10M.bin в encrypted.bin с ключом 123"
	./$(TARGET) test10M.bin encrypted.bin 123
	@echo "Дешифрование encrypted.bin в decrypted.bin с ключом 123"
	./$(TARGET) encrypted.bin decrypted.bin 123
	@echo "Сравнение исходного и расшифрованного файлов:"
	cmp test10M.bin decrypted.bin && echo "ТЕСТ ПРОЙДЕН" || echo "ТЕСТ НЕ ПРОЙДЕН"
	@rm -f encrypted.bin decrypted.bin

test_interrupt: $(TARGET) testfile
	@echo "Запустите программу и нажмите Ctrl+C:"
	./$(TARGET) test10M.bin interrupted.bin 123

clean:
	rm -f $(TARGET) test10M.bin encrypted.bin decrypted.bin interrupted.bin

.PHONY: all testfile test_secure test_interrupt clean