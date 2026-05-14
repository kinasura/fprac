CC = g++
CFLAGS = -Wall -pthread -std=c++11
LDFLAGS = -L. -lcaesar -lrt
TARGET = secure_copy

all: $(TARGET)

$(TARGET): secure_copy.cpp
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean