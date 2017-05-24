PREFIX=/usr/local
INSTALL=install -p

# Linux, other POSIX
CC=gcc
CFLAGS=-std=c99 -O3 -fPIC -MP -MMD -Iinclude/ -g -Wall -Wextra -Werror -c -o
LD=gcc
LDFLAGS=-std=c99 -g -o
LD_SHARED=gcc
LDFLAGS_SHARED=-std=c99 -g -shared -o
AR=ar
ARFLAGS=-rscD
SO=.so
EXE=

all: bin/liblsx.a bin/liblsx$(SO) test

install: bin/liblsx.a bin/liblsx$(SO)
	$(INSTALL) $^ $(PREFIX)/lib
	$(INSTALL) include/lsx.h include/lsx.hh $(PREFIX)/include

test: bin/lsx_test_twofish bin/lsx_test_sha256
	@echo Running tests...
	@echo Twofish...
	@bin/lsx_test_twofish
	@echo SHA-256...
	@bin/lsx_test_sha256
	@echo Tests passed!

bin/liblsx.a bin/liblsx$(SO): obj/lsx_twofish.o obj/lsx_sha256.o obj/lsx_bzero.o obj/lsx_random.o
bin/lsx_test_twofish: obj/lsx_test_twofish.o bin/liblsx.a
bin/lsx_test_sha256: obj/lsx_test_sha256.o bin/liblsx.a

bin/%$(SO):
	@echo Linking "$@"...
	@$(LD_SHARED) $(LDFLAGS_SHARED) "$@" $^

bin/%.a:
	@echo Archiving "$@"...
	@$(AR) $(ARFLAGS) "$@" $^

bin/%$(EXE):
	@echo Linking "$@"...
	@$(LD) $(LDFLAGS) "$@" $^

obj/%.o: src/%.c
	@echo Compiling "$<"...
	@$(CC) $(CFLAGS) "$@" "$<"

include/gen/twofish_tables.h: src/gen_twofish_tables.lua
	@echo Generating "$@"...
	@lua "$<" > "$@" || (rm -f "$@"; false)

clean:
	rm -f obj/*.o obj/*.d src/*.o *~ \#*\# bin/* lib/* *.d

include $(wildcard obj/*.d)
