ifeq "$(filter x64 x86,$(Platform))" ""
  $(error Need VS Environment)
endif

ifeq "$(SRCPATH)" ""
  $(error Need SRCPATH)
endif

.PHONY : all
all : xit.exe
	@echo make done.

DESTPATH	:= $(Platform)

CC 			:= cl.exe
LINK		:= link.exe

######## CFLAGS
CFLAGS		= /c /MP /GS- /Qpar /GL /analyze- /W4 /Gy /Zc:wchar_t /Zi /Gm- /Ox /Zc:inline /fp:precise /DWIN32 /DNDEBUG /D_UNICODE /DUNICODE /fp:except- /errorReport:none /GF /WX /Zc:forScope /GR- /Gd /Oy /Oi /MT /EHa /nologo /std:c++latest
CFLAGS      += /I"$(SRCPATH)"
CFLAGS		+= /Fd"$(DESTPATH)/"

ifeq "$(Platform)" "x86"
CFLAGS		+= /D_USING_V110_SDK71_
endif

CFLAGS      += $(MyCFLAGS)

######## LDFLAGS
LDFLAGS		= /MANIFEST:NO /LTCG /NXCOMPAT /DYNAMICBASE "kernel32.lib" "user32.lib" "gdi32.lib" "winspool.lib" "comdlg32.lib" "advapi32.lib" "shell32.lib" "ole32.lib" "oleaut32.lib" "uuid.lib" "odbc32.lib" "odbccp32.lib" /OPT:REF /INCREMENTAL:NO /OPT:ICF /ERRORREPORT:NONE /NOLOGO /MACHINE:$(Platform) /DEBUG:FULL
LDFLAGS		+= /LIBPATH:"$(DESTPATH)"

ifeq "$(Platform)" "x86"
LDFLAGS_CONSOLE	:= /SAFESEH /SUBSYSTEM:CONSOLE",5.01"
LDFLAGS_WINDOWS	:= /SAFESEH /SUBSYSTEM:WINDOWS",5.01"
else
LDFLAGS_CONSOLE	:= /SUBSYSTEM:CONSOLE
LDFLAGS_WINDOWS	:= /SUBSYSTEM:WINDOWS
endif

vpath %.cc  $(SRCPATH)
vpath %.h   $(SRCPATH)

vpath %.o 	$(DESTPATH)
vpath %.exe $(DESTPATH)

include Makefile.inc

$(DESTPATH) :
	@mkdir "$@"

%.o : %.cc | $(DESTPATH)
	$(CC) $(CFLAGS) /Fo"$(DESTPATH)/$(@F)" "$<"

xit.exe : $(OBJ) | $(DESTPATH)
	$(LINK) $(LDFLAGS) $(LDFLAGS_CONSOLE) /OUT:"$(DESTPATH)/$(@F)" $^
	@"$(DESTPATH)\\$(@F)" xit.exe E:\work\xit\$(Platform)\inner.dll