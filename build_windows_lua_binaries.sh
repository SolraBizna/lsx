#!/bin/sh

set -e -v

CC32="i686-pc-mingw32-gcc -mwin32 -shared -I include"
CC64="x86_64-w64-mingw32-gcc -shared -I include"
SOURCES="src/lsx_sha256.c src/lsx_twofish.c src/lsx_bzero.c src/lualsx.c -Wl,src/lualsx.def"

$CC32 -Os $SOURCES -o lsx.3251.dll \
winbin/lua-5.1.5_Win32_dllw4_lib/lua5.1.dll \
-I winbin/lua-5.1.5_Win32_dllw4_lib/include

$CC32 -Os $SOURCES -o lsx.3252.dll \
winbin/lua-5.2.3_Win32_dllw4_lib/lua52.dll \
-I winbin/lua-5.2.3_Win32_dllw4_lib/include

$CC64 -Os $SOURCES -o lsx.6451.dll \
winbin/lua-5.1.5_Win64_dllw4_lib/lua5.1.dll \
-I winbin/lua-5.1.5_Win64_dllw4_lib/include

$CC64 -Os $SOURCES -o lsx.6452.dll \
winbin/lua-5.2.3_Win64_dllw4_lib/lua52.dll \
-I winbin/lua-5.2.3_Win64_dllw4_lib/include

