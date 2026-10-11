CC = gcc
CFLAGS = -Wall -Wextra -std=c11
TARGET = ipgrep
SRC = main.c ip_matcher.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
