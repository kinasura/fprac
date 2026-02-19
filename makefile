CC = g++
CFLAGS = -Wall -Wextra -pedantic -fPIC
TARGET = libcaesar.so
TEST_SCRIPT = test_caesar.py
INPUT_FILE = input.txt

all: $(TARGET)

$(TARGET): caesar.cpp
	$(CC) -shared $(CFLAGS) $< -o $@

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/lib/
	sudo ldconfig

test: $(TARGET) $(INPUT_FILE)
	@echo "Шифрование входного файла с ключом 42 -> output.enc"
	python3 $(TEST_SCRIPT) ./$(TARGET) 42 $(INPUT_FILE) output.enc
	@echo "Дешифрование output.enc с тем же ключом -> output.dec"
	python3 $(TEST_SCRIPT) ./$(TARGET) 42 output.enc output.dec
	@echo "Сравнение исходного файла и расшифрованного:"
	cmp $(INPUT_FILE) output.dec && \
		echo "ТЕСТ ПРОЙДЕН: файлы идентичны" || \
		(echo "ТЕСТ НЕ ПРОЙДЕН: файлы различаются" && exit 1)
	@rm -f output.enc output.dec

clean:
	rm -f $(TARGET) output.enc output.dec

.PHONY: all install test clean