CFLAGS      += /DXSTDCOUT

UpperToken.o            : UpperToken.h xmsg.h xlog.h xhandle.h
xDll.o                  : xDll.h xmsg.h xlog.h xhandle.h xalloc.h
main.o                  : xmsg.h xlog.h xhandle.h UpperToken.h xDll.h

OBJ =  UpperToken.o \
       xDll.o \
       main.o