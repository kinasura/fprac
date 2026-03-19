CC = g++
CFLAGS = -Wall -pthread -std=c++11
LDFLAGS = -L. -lcaesar -lrt
TARGET = secure_copy

all: $(TARGET)

$(TARGET): secure_copy.cpp libcaesar.so
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET) log.txt