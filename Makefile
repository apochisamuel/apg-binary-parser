CC ?= clang
CXX ?= clang++
CFLAGS ?= -O1 -g -Wall -Wextra -Wpedantic -std=c99 -I src
CXXFLAGS ?= -O1 -g -std=c++11 -I src
SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)
.PHONY: all clean test seeds fuzzers pocs
all: libapg.a tools/gen_seeds tests/test_header tests/test_entries
libapg.a: $(OBJ)
	ar rcs $@ $(OBJ)
tools/gen_seeds: tools/gen_seeds.c
	$(CC) $(CFLAGS) $< -o $@
tests/test_header: tests/test_header.c libapg.a
	$(CC) $(CFLAGS) $< libapg.a -o $@
tests/test_entries: tests/test_entries.c libapg.a
	$(CC) $(CFLAGS) $< libapg.a -o $@
seeds: tools/gen_seeds
	./tools/gen_seeds fuzz/corpus
pocs:
	for c in pocs/gen_*.c; do $(CC) -O1 -g -std=c99 -I pocs $$c -o $${c%.c}; done
fuzzers: seeds
	mkdir -p out/fuzzobj
	for c in $(SRC); do $(CC) -O1 -g -std=c99 -I src -fsanitize=address,fuzzer-no-link -c $$c -o out/fuzzobj/$$(basename $$c .c).o; done
	for f in parse_fuzzer entry_fuzzer resolve_fuzzer; do $(CXX) $(CXXFLAGS) -fsanitize=fuzzer,address fuzz/$$f.cc out/fuzzobj/*.o -o out/$$f; done
test: all seeds
	./tests/test_header
	./tests/test_entries
clean:
	rm -f src/*.o libapg.a tools/gen_seeds tests/test_header tests/test_entries
	find pocs -maxdepth 1 -type f -name 'gen_poc*' ! -name '*.c' -delete
	rm -rf out/*
