# Linux, other POSIX
CC=gcc
CCFLAGS=-std=c99 -O3 -fpic -MP -MMD -Iinclude/ -g -Wall -Wextra -Werror -c -o
LD=gcc
LDFLAGS=-std=c99 -g -o
LD_SHARED=gcc
LDFLAGS_SHARED=-std=c99 -g -shared -o
AR=ar
ARFLAGS=-rscD
SO=.so
EXE=

all: bin/liblsx.a bin/liblsx$(SO)

test: bin/lsx_test
	@echo Running tests...
	@bin/lsx_test
	@echo Tests passed!

bin/liblsx.a bin/liblsx$(SO): obj/lsx_twofish.o
bin/lsx_test: obj/lsx_test.o bin/liblsx.a

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
	@$(CC) $(CCFLAGS) "$@" "$<"

include/gen/twofish_tables.h: src/gen_twofish_tables.lua
	@echo Generating "$@"...
	@lua "$<" > "$@" || (rm -f "$@"; false)

clean:
	rm -f obj/*.o obj/*.d *~ \#*\# bin/* lib/* *.d

include $(wildcard obj/*.d)
