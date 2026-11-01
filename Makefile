CC = gcc
CFLAGS = -Wall -Wextra -std=c11
TARGET = ipgrep
SRC = main.c ip_matcher.c ip_cidr.c ip_cidr_trie.c ip_cidr_store.c

.PHONY: all clean run functional-test test help

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)

run: $(TARGET)
	./$(TARGET)

help:
	@echo "Available targets:"
	@echo "  all              Build ipgrep"
	@echo "  run              Build and run ipgrep"
	@echo "  functional-test  Run functional tests"
	@echo "  test             Run all tests"
	@echo "  clean            Remove build artifacts"
	@echo "  help             Show this help message"

functional-test: $(TARGET)
	python3 -m unittest discover -s tests/functional -p 'test_*.py' -v

test: functional-test

clean:
	rm -f $(TARGET)
