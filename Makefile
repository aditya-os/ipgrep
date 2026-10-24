CC = gcc
CFLAGS = -Wall -Wextra -std=c11
TARGET = ipgrep
SRC = main.c ip_matcher.c ip_cidr.c ip_cidr_trie.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
