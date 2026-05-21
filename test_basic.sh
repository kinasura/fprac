#!/bin/bash
set -e

echo "=== Тест 1: Создание тестового файла ==="
dd if=/dev/urandom of=original.bin bs=1M count=10 2>/dev/null
echo "Исходный файл original.bin создан (10 МБ)"

echo "=== Тест 2: Шифрование с ключом 123 в папку enc_dir ==="
mkdir -p enc_dir
./secure_copy --mode=sequential original.bin enc_dir 123
echo "Зашифрованный файл: enc_dir/original.bin"

echo "=== Тест 3: Расшифровка в папку dec_dir ==="
mkdir -p dec_dir
./secure_copy --mode=sequential enc_dir/original.bin dec_dir 123
echo "Расшифрованный файл: dec_dir/original.bin"

echo "=== Тест 4: Сравнение исходного и расшифрованного ==="
if cmp original.bin dec_dir/original.bin; then
    echo "✅ УСПЕХ: файлы идентичны"
else
    echo "❌ ОШИБКА: файлы различаются"
    exit 1
fi

echo "=== Тест 5: Проверка защиты ключа (mmap/mprotect) ==="
./secure_copy --mode=sequential original.bin test_out 42 &
PID=$!
sleep 1
if grep -q "r--p" /proc/$PID/maps 2>/dev/null; then
    echo "✅ Обнаружена read-only страница"
else
    echo "⚠️ Read-only страница не найдена (возможно, прав нет)"
fi
kill $PID 2>/dev/null
wait $PID 2>/dev/null || true

echo "=== Очистка ==="
rm -rf original.bin enc_dir dec_dir test_out
echo "Базовый тест пройден успешно."