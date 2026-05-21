CC = g++
CFLAGS = -Wall -Wextra -pedantic -fPIC -D_GNU_SOURCE
TARGET = libcaesar.so

all: $(TARGET)

$(TARGET): caesar.cpp
	$(CC) -shared $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGET)

.PHONY: all clean