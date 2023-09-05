#ifndef _xit_H_
#define _xit_H_

// 注意：对 PE 结构没有做 严格的合法性 检查。
// 注意：请在加上编译选项： /EHa ，以使 Windows 异常能被 c++ 异常捕获。
// 为保持兼容性，特意不使用类，为记。

#include <limits>
#include <memory>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#undef NOMINMAX
#undef WIN32_LEAN_AND_MEAN
#include <tchar.h>
#include <tlhelp32.h>

static_assert(sizeof(size_t) == sizeof(void*), "size_t != void*");

class xdll {
 public:
  enum ERROR_ENUM : uint32_t {
    XSuccess,
    XOpenProcessToken,
    XLookupPrivilegeValue,
    XAdjustTokenPrivileges,
    XCreateToolhelp32Snapshot,
    XProcess32First,
    XGetPID,
    XGetModule,
    XCreateFile,
    XGetFileSizeEx,
    XLoadFile,
    XLoadFileLocalAlloc,
    XLoadFileLocalLock,
    XReadFile,
    XLocalAlloc,
    XLocalLock,
    XDecode,
    XFindResource,
    XLoadResource,
    XLockResource,
    XSizeofResource,
    XVirtualAllocEx,
    XMappingLock,
    XMappingHeader,
    XMappingSection,
    XMapping,
    XOpenProcess,
    XCreateRemoteThread,
    XWaitForSingleObject_timeout,
    XWaitForSingleObject_fail,
    XGetExitCodeThread,
    XRemoteThread,
    XDoShellcodeNew,
    XWriteProcessMemory,
    XReadProcessMemory,
    XImportDLL,
    XSetImageBase,
    XNoExport,
    XIndex,
    XNoFind,
    XNoMod,
    XGetModuleHandleA,
    XGetProcAddress,
    XLocalDllProcAddr,
  };
 public:
  using Result = unsigned long long;
  static_assert(8 == sizeof(Result), "8 != ull");
  static_assert(4 == sizeof(ERROR_ENUM), "4 != enum");
  static_assert(4 == sizeof(DWORD), "4 != dword");
 private:
  static inline Result XERROR(const ERROR_ENUM e, const DWORD ec = GetLastError()) {
    return (((e | 0x80000000) << 32) | ec);
  }
  template<typename T> Result XRETURN(const T v) {
    return (Result)v;
  }
 public:
  /// 获得 XIT_ERROR_ENUM 错误码。
  static inline ERROR_ENUM Error(const Result res) {
    return (ERROR_ENUM)((res >> 32) & 0x7FFFFFFF);
  }
  static inline DWORD ErrorEx(const Result res) {
    return (DWORD)(res & 0xFFFFFFFF);
  }
  static inline bool IsOK(const Result res) {
    return XSuccess == Error(res);
  }
  /// 获得 GetLastError 错误码。
  DWORD ErrorEx(const Result res);
  /// 检测是否存在错误码。
  bool IsOK(const Result res);




  /// 内部资源保持类。
  template<typename T>
  class xhold {
   public:
    xhold() : _h() {}
    xhold(const xhold&) = delete;
    xhold&operator=(const xhold&) = delete;
   public:
    using free_function = void(*)(const T&);
    xhold(const T& v, free_function f) : _h(v), _free(f) {}
    void free() {
      if (nullptr == _free) return;
      _free(_h);
      _h = T();
      _free = nullptr;
    }
    ~xhold() { free(); }
    operator T() const { return _h; }
    operator bool() const { return T() != _h; }
   public:
    T _h;
    free_function _free = nullptr;
  };
  class xHandle {
   public:
    xHandle() : _h(nullptr) {}
    xHandle(const xHandle&) = delete;
    xHandle&operator=(const xHandle&) = delete;
    xHandle(const HANDLE h) : _h(h) {}
    void free() {
      if (nullptr == _h) return;
      CloseHandle(_h);
      _h = nullptr;
    }
    ~xHandle() { free(); }
    operator HANDLE() const { return _h; }
    operator bool() const { return nullptr != _h; }
    HANDLE*operator&() { return &_h; }
   public:
    HANDLE _h;
  };

  class xLocal {
   public:
    xLocal() : _h(nullptr), _lp(nullptr) {}
    xLocal(const xLocal&) = delete;
    xLocal&operator=(const xLocal&) = delete;
    xLocal(const HLOCAL h) : _h(h), _lp(nullptr) {}
    xLocal(const UINT uFlags, const SIZE_T uBytes) : _h(nullptr), _lp(nullptr) {
      _h = LocalAlloc(uFlags, uBytes);
    }
    void UnLock() {
      if (nullptr == _h) return;
      if (nullptr == _lp) return;
      LocalUnlock(_h);
      _lp = nullptr;
    }
    void free() {
      if (nullptr == _h) return;
      UnLock();
      LocalFree(_h);
      _h = nullptr;
    }
    ~xLocal() { free(); }
    operator HLOCAL() const { return _h; }
    operator bool() const { return nullptr != _h; }
    LPVOID Lock() {
      if (nullptr == _h) return nullptr;
      if (nullptr != _lp) return _lp;
      _lp = LocalLock(_h);
      return _lp;
    }
   public:
    HLOCAL _h;
    LPVOID _lp;
  };

  class xMemory {
   public:
    xMemory() : _hProcess(nullptr), _mem(nullptr) {}
    xMemory(const xMemory&) = delete;
    xMemory&operator=(const xMemory&) = delete;
    xMemory(const HANDLE hProcess, const SIZE_T dwSize) :
        _hProcess(hProcess), _mem(nullptr) {
      _mem = VirtualAllocEx(hProcess, nullptr, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    void free() {
      if (nullptr == _mem) return;
      VirtualFreeEx(_hProcess, _mem, 0, MEM_RELEASE);
      _mem = nullptr;
    }
    ~xMemory() { free(); }
    operator LPVOID() const { return _mem; }
    operator bool() const { return nullptr != _mem; }
   public:
    HANDLE _hProcess;
    HANDLE _mem;
  };
 private:
  bool Error(const ERROR_ENUM e = XSuccess, const DWORD ec = 0) {
    _e = e;
    _ec = (XSuccess != e && 0 == ec) ? GetLastError() : ec;
    return XSuccess == e;
  }
 public:
  xdll() : _e(XSuccess), _ec(0), _hProcess(nullptr) {}
 public:
  /// 进程提权。
  bool UpperToken() {
    HANDLE TokenHandle;
    if (FALSE == OpenProcessToken(_hProcess,
                                  TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                  &TokenHandle)) {
      return Error(XOpenProcessToken);
    }

    TOKEN_PRIVILEGES NewState;
    NewState.PrivilegeCount = 1;
    if (FALSE == LookupPrivilegeValue(nullptr,
                                      SE_DEBUG_NAME,
                                      &(NewState.Privileges[0].Luid))) {

      return Error(XLookupPrivilegeValue);
    }

    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (FALSE == AdjustTokenPrivileges(TokenHandle,
                                       FALSE,
                                       &NewState,
                                       sizeof(NewState),
                                       nullptr,
                                       nullptr)) {
      return Error(XAdjustTokenPrivileges);
    }

    return Error();
  }
 private:
  static inline DWORD PickPID(LPCTSTR pid) {
    try {
      if (nullptr == pid) return 0;
      if (0 == _tcslen(pid)) return 0;
      auto str_end = (LPTSTR)pid;
      const auto PID = _tcstoul(pid, &str_end, 16);
      // 完全转换完成，并转换成功才行。
      if(TEXT('\0') != *str_end) return 0;
      if(ULONG_MAX == PID) return 0;
      return PID;
    } catch (...) {
      return 0;
    }
  }
 public:
  /// 指定 PID 或 进程名，获取 PID 。成功则返回 DWORD 。
  DWORD GetPID(LPCTSTR pid) {
    const auto PID = PickPID(pid);
    if (0 != PID) return PID;

    xHandle hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) {
      return Error(XCreateToolhelp32Snapshot);
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (FALSE == Process32First(hSnapshot, &pe32)) {
      return Error(XProcess32First);
    }

    do {
      if (0 == _tcsicmp(pid, pe32.szExeFile)) {
        return pe32.th32ProcessID;
      }
    } while (FALSE != Process32Next(hSnapshot, &pe32));

    return Error(XGetPID);
  }
  /// 指定 HMOUDLE 。成功则返回 HMOUDLE 。
  HMODULE GetModule(LPCTSTR hmod) {
    try {
      if (nullptr == hmod) return nullptr;
      if (0 == _tcslen(hmod)) return nullptr;
      auto str_end = (LPTSTR)hmod;
#ifdef _WIN64
      auto MOD = _tcstoull(hmod, &str_end, 16);
      if (ULLONG_MAX == MOD) {
        ERROR(XGetModule, 1);
        return nullptr;
      }
#else
      auto MOD = _tcstoul(hmod, &str_end, 16);
      if (ULONG_MAX == MOD) {
        ERROR(XGetModule, 1);
        return nullptr;
      }
#endif
      // 完全转换完成，并转换成功才行。
      if (TEXT('\0') != *str_end) {
        ERROR(XGetModule, 2);
        return nullptr;
      }
      if (0 == MOD) {
        ERROR(XGetModule, 3);
        return nullptr;
      }

      // 允许缺省 尾部 4 个 0 ，这里判断并自动补齐。
      if (MOD & 0xFFFF) MOD <<= 16;
      
      return (HMODULE)MOD;
    } catch (...) {
      ERROR(XGetModule, 4);
      return nullptr;
    }
  }
 public:
  /// 解密函数。
  using Decode_Function = bool(*)(LPVOID BIN, LPVOID SRC, const size_t size);
  /// 不加密，仅仅是简单 COPY 。
  static inline bool NoDecode(LPVOID BIN, LPVOID SRC, const size_t size) {
    try {
      CopyMemory(BIN, SRC, size);
      return true;
    } catch(...) {
      return false;
    }
  }
 public:
  /// 指定加载文件。成功则返回 HLOCAL。
  std::shared_ptr<xLocal> LoadFile(LPCTSTR lpFileName, Decode_Function Decode = &NoDecode) {
    // 打开文件。
    xHandle hFile = CreateFileW(lpFileName,
                                GENERIC_READ,
                                FILE_SHARE_READ,
                                nullptr,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_READONLY,
                                nullptr);
    if (INVALID_HANDLE_VALUE == hFile) {
      Error(XCreateFile);
      return nullptr;
    }

    // 查询大小。
    LARGE_INTEGER FileSize;
    if (FALSE == GetFileSizeEx(hFile, &FileSize)) {
      Error(XGetFileSizeEx);
      return nullptr;
    }
    if (0 != FileSize.HighPart) {
      Error(XLoadFile, 1);
      return nullptr;
    }

    // 申请内存。
    const auto uBytes = FileSize.LowPart;
    xLocal hMem(LMEM_MOVEABLE | LMEM_ZEROINIT, uBytes);
    if (nullptr == hMem) {
      Error(XLoadFileLocalAlloc);
      return nullptr;
    }

    // 锁定内存。
    auto lpBuffer = hMem.Lock();
    if (nullptr == lpBuffer) {
      Error(XLoadFileLocalLock);
      return nullptr;
    }

    // 读取文件。
    DWORD NumberOfBytesRead = 0;
    if (FALSE == ReadFile(hFile, lpBuffer, uBytes, &NumberOfBytesRead, nullptr)) {
      Error(XReadFile);
      return nullptr;
    }

    // 释放文件句柄。
    hFile.free();

    // 申请可写缓存。
    std::shared_ptr<xLocal> hMEM = std::make_shared<xLocal>(LMEM_MOVEABLE | LMEM_ZEROINIT, uBytes);
    if (!*hMEM) {
      Error(XLocalAlloc);
      return nullptr;
    }

    // 锁定内存。
    auto BIN = hMEM->Lock();
    if (nullptr == BIN) {
      Error(XLocalLock);
      return nullptr;
    }
  
    const auto ok = Decode(BIN, lpBuffer, uBytes);
  
    hMem.free();
    hMEM->UnLock();

    if (!ok) {
      Error(XDecode);
      hMEM->free();
      return nullptr;
    }

    return hMEM;
  }
  
  /// 指定加载资源。成功则返回 HLOCAL。
  std::shared_ptr<xLocal> LoadRes(HMODULE          hModule,
                                  LPCTSTR          lpName,
                                  LPCTSTR          lpType,
                                  Decode_Function  Decode = &NoDecode){
    // 加载资源。注意到：资源句柄无需释放。
    auto hResInfo = FindResource(hModule, lpName, lpType);
    if (nullptr == hResInfo) {
      Error(XFindResource);
      return nullptr;
    }

    auto hResData = LoadResource(hModule, hResInfo);
    if (nullptr == hResData) {
      Error(XLoadResource);
      return nullptr;
    }

    auto RES = LockResource(hResData);
    if (nullptr == RES) {
      Error(XLockResource);
      return nullptr;
    }

    auto uBytes = SizeofResource(hModule, hResInfo);
    if (0 == uBytes) {
      Error(XSizeofResource);
      return nullptr;
    }

    // 申请可写缓存。
    std::shared_ptr<xLocal> hMem = std::make_shared<xLocal>(LMEM_MOVEABLE | LMEM_ZEROINIT, uBytes);
    if (!*hMem) {
      Error(XLocalAlloc);
      return nullptr;
    }

    auto BIN = hMem->Lock();
    if (nullptr == BIN) {
      Error(XLocalLock);
      return nullptr;
    }

    const auto ok = Decode(BIN, RES, uBytes);
    
    hMem->UnLock();

    if (!ok) {
      hMem->free();
      Error(XDecode, 2);
      return nullptr;
      }

    return hMem;
  }
  /// 平铺 DLL 。成功则返回 LPVOID 。
  std::shared_ptr<xMemory> Mapping(xLocal& hMem) {
    auto BIN = hMem.Lock();
    if (nullptr == BIN) {
      Error(XMappingLock);
      return nullptr;
    }
    try {
      const auto& DosHeader = *(IMAGE_DOS_HEADER*)BIN;
      const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
      // 获取镜像大小。
      const auto SizeOfImage = NtHeaders.OptionalHeader.SizeOfImage;

      auto PE = std::make_shared<xMemory>(_hProcess, SizeOfImage);
      if (!*PE) {
        Error(XMapping);
        hMem.UnLock();
        return nullptr;
      }

      // 所有 头 + 节表 头大小。
      const SIZE_T SizeOfHeaders = NtHeaders.OptionalHeader.SizeOfHeaders;

      // 写入所有 头 + 节表 头。
      if (FALSE == WriteProcessMemory(_hProcess, *PE, &DosHeader, SizeOfHeaders, nullptr)) {
        Error(XMappingHeader);
        hMem.UnLock();
        return nullptr;
      }

      // 节表数量。
      const size_t NumberOfSections = NtHeaders.FileHeader.NumberOfSections;

      // 获取第一个 节表头 的地址。
      auto pSectionHeader = (IMAGE_SECTION_HEADER*)((size_t)&NtHeaders + sizeof(NtHeaders));

      // 写入所有 节表。
      for (size_t i = 0; i < NumberOfSections; ++i) {
        if ((0 == pSectionHeader->VirtualAddress) || (0 == pSectionHeader->SizeOfRawData)) {
          ++pSectionHeader;
          continue;
        }

        auto src = (void*)((size_t)&DosHeader + pSectionHeader->PointerToRawData);
        auto dst = (void*)((size_t)(*PE)._mem + pSectionHeader->VirtualAddress);

        if (FALSE == WriteProcessMemory(_hProcess, dst, src, pSectionHeader->SizeOfRawData, nullptr)) {
          Error(XMappingSection);
          hMem.UnLock();
          return nullptr;
        }

        ++pSectionHeader;
      }

      hMem.UnLock();
      return PE;
    } catch(...) {
      hMem.UnLock();
      Error(XMapping, 1);
      return nullptr;
    }
  }
 public:
  /// 打开进程。
  bool OpenProcess(const DWORD PID) {
    _hProcess._h = ::OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        TRUE, PID);
    if (!_hProcess) {
      return Error(XOpenProcess);
    }
    return ERROR();
  }
  bool OpenProcess(LPCTSTR pid) {
    const auto PID = GetPID(pid);
    if (0 == PID) return false;
    return OpenProcess(PID);
  }
  
  // 注意：以下函数，传入的句柄，都不主动释放。
 public:
  /// 执行远程线程。成功则返回 线程 DWORD 。
  DWORD RemoteThread(LPTHREAD_START_ROUTINE shellcode, LPVOID lpParam) {
    
    xHandle hThread = CreateRemoteThread(_hProcess, nullptr, 0, shellcode, lpParam, 0, nullptr);
    if (!hThread) {
      return Error(XCreateRemoteThread);
    }

    const auto wait = WaitForSingleObject(hThread, INFINITE);
    if (WAIT_TIMEOUT == wait) {

      return Error(XWaitForSingleObject_timeout);
    }   {
      const auto r = XERROR(XWaitForSingleObject_timeout);
      TerminateThread(hThread, 0);
      CloseHandle(hThread);
      return r;
      }
    if(WAIT_FAILED == wait ||  WAIT_OBJECT_0 != wait)
      {
      const auto r = XERROR(XWaitForSingleObject_fail);
      TerminateThread(hThread, 0);
      CloseHandle(hThread);
      return r;
      }

    DWORD ec;
    if(FALSE == GetExitCodeThread(hThread, &ec))
      {
      const auto r = XERROR(XGetExitCodeThread);
      TerminateThread(hThread, 0);
      CloseHandle(hThread);
      return r;
      }

    CloseHandle(hThread);
    if(XSuccess != ec) return XERROR(XRemoteThread, ec);

    return XRETURN(ec);
  }
 public:
  ERROR_ENUM  _e;
  DWORD       _ec;
  xHandle     _hProcess;
};

namespace xit
  {
////////////////////////////////////////////////////////////////
enum ERROR_ENUM
  {
  XSuccess,
  XOpenProcessToken,
  XLookupPrivilegeValue,
  XAdjustTokenPrivileges,
  XCreateToolhelp32Snapshot,
  XProcess32First,
  XGetPID,
  XGetModule,
  XCreateFile,
  XGetFileSizeEx,
  XLoadFile,
  XLoadFileLocalAlloc,
  XLoadFileLocalLock,
  XReadFile,
  XLocalAlloc,
  XLocalLock,
  XDecode,
  XFindResource,
  XLoadResource,
  XLockResource,
  XSizeofResource,
  XVirtualAllocEx,
  XMappingLock,
  XMappingHeader,
  XMappingSection,
  XMapping,
  XOpenProcess,
  XCreateRemoteThread,
  XWaitForSingleObject_timeout,
  XWaitForSingleObject_fail,
  XGetExitCodeThread,
  XRemoteThread,
  XDoShellcodeNew,
  XWriteProcessMemory,
  XReadProcessMemory,
  XImportDLL,
  XSetImageBase,
  XNoExport,
  XIndex,
  XNoFind,
  XNoMod,
  XGetModuleHandleA,
  XGetProcAddress,
  XLocalDllProcAddr,
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

/// 打开进程。成功则返回 HANDLE 。
Result OpenProcess(const DWORD PID);
Result OpenProcess(LPCTSTR pid);

// 注意：以下函数，传入的句柄，都不主动释放。

/// 执行远程线程。成功则返回 线程 DWORD 。
Result RemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE shellcode, LPVOID lpParam);

/// 指定加载 DLL 。成功则返回 PE 。注意：PE 需已 Mapping 。
Result LoadDll(HANDLE hProcess, LPVOID PE);

/// 指定加载文件为 DLL 。成功则返回 LPVOID 。
Result LoadDll(HANDLE hProcess, LPCTSTR lpFileName, Decode_Function Decode = &NoDecode);
Result LoadDll(LPCTSTR pid, LPCTSTR lpFileName, Decode_Function Decode = &NoDecode);

/// 指定加载资源为 DLL 。成功则返回 LPVOID 。
Result LoadDll(HANDLE           hProcess,
               HMODULE          hModule,
               LPCTSTR          lpName,
               LPCTSTR          lpType,
               Decode_Function  Decode = &NoDecode);
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

/// 指定卸载 DLL 。
UnloadDllST UnloadDll(HANDLE hProcess, LPVOID PE, const bool release_pe = true);
/// 指定卸载 DLL 。
UnloadDllST UnloadDll(LPCTSTR pid, LPVOID PE);

/// 本地查找指定模块的导出函数。
Result LocalDllProcAddr(LPVOID PE, LPCSTR lpProcName, const bool fuzzy = false);

/// 远程查找指定模块的导出函数。
Result RemoteDllProcAddr(HANDLE hProcess, LPVOID PE, LPCSTR lpProcName, const bool fuzzy = false);
////////////////////////////////////////////////////////////////
  }

#endif  //_xit_H_