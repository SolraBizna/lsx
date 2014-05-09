package = "luaLSX"
version = "0.1-1"
source = {
   url="data:"
}
description = {summary = "A Lua binding to LibSolraXandria"}
dependencies = {"lua >= 5.1, < 5.3"}
build = {
   type = "builtin",
   modules = {
      lsx = {
         sources={"src/lsx_sha256.c","src/lsx_twofish.c","src/lsx_bzero.c","src/lualsx.c"},
         incdirs={"include"},
      },
   }
}
