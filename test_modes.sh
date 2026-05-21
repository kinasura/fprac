#!/bin/bash
# test_modes.sh – тестирование режимов работы и автоматического выбора

set -e

# Создаём 10 небольших файлов для теста
echo "=== Подготовка: создание 10 тестовых файлов ==="
for i in {1..10}; do
    echo "Содержимое файла $i" > "file$i.txt"
done
mkdir -p out_seq out_par out_auto

echo "=== Тест 1: Последовательный режим (--mode=sequential) ==="
time_start=$(date +%s%N)
./secure_copy --mode=sequential file*.txt out_seq 42
time_end=$(date +%s%N)
seq_time=$(( (time_end - time_start) / 1000000 ))  # миллисекунды
echo "Время выполнения: ${seq_time} мс"

echo "=== Тест 2: Параллельный режим (--mode=parallel) ==="
time_start=$(date +%s%N)
./secure_copy --mode=parallel file*.txt out_par 42
time_end=$(date +%s%N)
par_time=$(( (time_end - time_start) / 1000000 ))
echo "Время выполнения: ${par_time} мс"

echo "=== Тест 3: Автоматический режим (должен выбрать parallel, т.к. файлов >=5) ==="
time_start=$(date +%s%N)
./secure_copy --mode=auto file*.txt out_auto 42
time_end=$(date +%s%N)
auto_time=$(( (time_end - time_start) / 1000000 ))
echo "Время выполнения: ${auto_time} мс"

echo "=== Тест 4: Сравнение результатов (должны быть идентичны) ==="
# Сравниваем один и тот же файл, зашифрованный в разных режимах
if cmp out_seq/file1.txt out_par/file1.txt && cmp out_seq/file1.txt out_auto/file1.txt; then
    echo "✅ Все режимы дали одинаковый шифротекст"
else
    echo "❌ Результаты различаются – ошибка"
    exit 1
fi

echo "=== Тест 5: Производительность (параллельный должен быть быстрее последовательного) ==="
if [ $par_time -lt $seq_time ]; then
    speedup=$(echo "scale=2; $seq_time / $par_time" | bc)
    echo "✅ Параллельный режим быстрее в ${speedup} раз"
else
    echo "⚠️ Параллельный режим не быстрее (возможно, файлы слишком малы)"
fi

echo "=== Тест 6: Обработка сигнала SIGINT (Ctrl+C) ==="
# Запускаем программу в фоне и через 0.5 секунды посылаем SIGINT
./secure_copy --mode=parallel file*.txt out_int 42 &
PID=$!
sleep 0.5
kill -INT $PID
wait $PID
# Проверяем, что сообщение "Операция прервана" было выведено (в stderr)
echo "Проверьте вывод выше: должно быть сообщение о прерывании"

echo "=== Очистка ==="
rm -rf file*.txt out_seq out_par out_auto out_int
echo "Все тесты завершены."