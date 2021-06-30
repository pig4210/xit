#ifndef _XIT_H_
#define _XIT_H_

// 特性降级适配 VS2013 。
// 注意：对 PE 结构没有做 严格的合法性 检查。
// 注意：请在加上编译选项： /EHa ，以使 Windows 异常能被 c++ 异常捕获。

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static_assert(sizeof(size_t) == sizeof(void*), "size_t != void*");

namespace xit
  {
////////////////////////////////////////////////////////////////
enum ERROR_ENUM
  {
  Success,
  XOpenProcessToken,
  XLookupPrivilegeValue,
  XAdjustTokenPrivileges,
  XCreateToolhelp32Snapshot,
  XProcess32First,
  XGetPID,
  XGetModule,
  XCreateFile,
  XGetFileSizeEx,
  XLarge,
  XLocalAlloc,
  XLocalLock,
  XReadFile,
  XDecode,
  XFindResource,
  XLoadResource,
  XLockResource,
  XVirtualAlloc,
  XSizeofResource,
  XLoadRes,
  XVirtualAllocEx,
  XMappingLock,
  XMappingHeader,
  XMappingSection,
  XMapping,
  XOpenProcess,
  XDoShellcodeNew,
  XWriteProcessMemory,
  XCreateRemoteThread,
  XWaitForSingleObject_timeout,
  XWaitForSingleObject_fail,
  XGetExitCodeThread,
  XDoShellcode,
  XImportDLL,
  XSetImageBase,
  XIndex,
  XNoMod,
  XGetModuleHandleA,
  XGetProcAddress,
  XLocalDllProcAddr,
  XReadProcessMemory,
  };

typedef unsigned long long Result;

static_assert(8 == sizeof(Result),      "8 != ull");
static_assert(4 == sizeof(ERROR_ENUM),  "4 != enum");
static_assert(4 == sizeof(DWORD),       "4 != dword");

/// 获得 XIT_ERROR_ENUM 错误码。
ERROR_ENUM Error(const Result res);
/// 获得 GetLastError 错误码。
DWORD ErrorEx(const Result res);
/// 检测是否存在错误码。
bool IsOK(const Result res);

/// 进程提权。
Result UpperToken(HANDLE hProcess = GetCurrentProcess());

/// 指定 PID 或 进程名，获取 PID 。成功则返回 DWORD 。
Result GetPID(LPCTSTR pid);

/// 指定 HMOUDLE 。成功则返回 HMOUDLE 。
Result GetModule(LPCTSTR hmod);

/// 不加密，仅仅是简单 COPY 。
bool NoDecode(LPVOID BIN, LPVOID SRC, const size_t size);

/// 解密函数。
using Decode_Function = bool(*)(LPVOID BIN, LPVOID SRC, const size_t size);

/// 指定加载文件。成功则返回 HLOCAL。
Result LoadFile(LPCTSTR lpFileName, Decode_Function Decode = &NoDecode);

/// 指定加载资源。成功则返回 HLOCAL。
Result LoadRes(HMODULE          hModule,
               LPCTSTR          lpName,
               LPCTSTR          lpType,
               Decode_Function  Decode = &NoDecode);

/// 平铺 DLL 。成功则返回 LPVOID 。
Result Mapping(HANDLE hProcess, LPVOID BIN);

Result OpenProcess(const DWORD PID);
Result OpenProcess(LPCTSTR pid);

/// 指定加载 DLL 。成功则返回 PE 。注意：失败不主动释放资源。
Result LoadDll(HANDLE hProcess, LPVOID PE);

/// 指定加载文件为 DLL 。成功则返回 LPVOID 。注意：失败主动释放资源。
Result LoadDll(LPCTSTR pid, LPCTSTR lpFileName, Decode_Function Decode = &NoDecode);

/// 指定加载资源为 DLL 。成功则返回 LPVOID 。注意：失败主动释放资源。
Result LoadDll(LPCTSTR          pid,
               HMODULE          hModule,
               LPCTSTR          lpName,
               LPCTSTR          lpType,
               Decode_Function  Decode = &NoDecode);

struct UnloadDllST
  {
  Result tls;
  Result main;
  Result import;
  Result ex;
  };

/// 指定卸载 DLL 。注意：失败不主动释放资源。
UnloadDllST UnloadDll(HANDLE hProcess, LPVOID PE);
/// 指定卸载 DLL 。注意：失败主动释放资源。
UnloadDllST UnloadDll(LPCTSTR pid, LPVOID PE);

/// 本地查找指定模块的导出函数。
Result LocalDllProcAddr(LPVOID PE, LPCSTR lpProcName, const bool fuzzy = false);

/// 远程查找指定模块的导出函数。
Result RemoteDllProcAddr(HANDLE hProcess, LPVOID PE, LPCSTR lpProcName, const bool fuzzy = false);
////////////////////////////////////////////////////////////////
  }

#endif  //_XIT_H_