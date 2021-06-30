RESID := 1111

CFLAGS += /Zc:threadSafeInit- /DRESID=$(RESID)

vpath %.res $(DSTPATH)

LUA := E:\work\Lua\x64\lua.exe

$(ProjectName)_inner.dll : test.o | $(DSTPATH)
	$(LINK) $(LDFLAGS) /DLL $(LDFLAGS_WINDOWS) /OUT:"$(DSTPATH)/$(@F)" $(^F)
	@echo.

$(ProjectName).res : $(ProjectName)_inner.dll
	cd "$(DSTPATH)" && $(LUA) -e "local ss = '#include \x22winres.h\x22\n\nLANGUAGE LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED\n\n$(RESID)    BIN    \x22$(<F)\x22'; local file = io.open( [[$(ProjectName).rc]], 'wb' ); file:write( ss ); file:close();"
	cd "$(DSTPATH)" && rc /nologo /fo"$@" "$(ProjectName).rc"
	echo.

vpath %.x $(DSTPATH)
exdst.x : $(ProjectName).exe $(ProjectName)_inner.dll
	@echo.
	@"$(DSTPATH)\\$(ProjectName).exe" $(ProjectName).exe
	@echo.
	@"$(DSTPATH)\\$(ProjectName).exe" $(ProjectName).exe "$(DSTPATH)\\$(ProjectName)_inner.dll"
	@echo.
	@echo.>"$(DSTPATH)\\$(@F)"

.PHONY : exdst
exdst : exdst.x


xit.o                   : xit.h
main.o                  : xit.h

OBJ := $(ProjectName).res xit.o main.o