CC = g++
CFLAGS = -Wall -pthread -std=c++11
LDFLAGS = -L. -lcaesar -lrt   # -lrt может понадобиться для clock_gettime
TARGET = secure_copy

all: $(TARGET)

$(TARGET): secure_copy.cpp
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET) log.txt

.PHONY: all clean