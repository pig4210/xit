#ifndef _XDLL_H_
#define _XDLL_H_

#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

class xhandle;

bool LoadLibraryW(DWORD PID, const std::string& dllfile);

#endif  //_XDLL_H_