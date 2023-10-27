#ifndef _xit_H_
#define _xit_H_

// 注意：对 PE 结构没有做 严格的合法性 检查。
// 注意：请在加上编译选项： /EHa ，以使 Windows 异常能被 c++ 异常捕获。
// 多次尝试封装句柄类用于自动释放资源，但最终效果不理想，或是过于繁琐，或是使流程不够清晰。
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
#include <Psapi.h>

static_assert(sizeof(size_t) == sizeof(void*), "size_t != void*");

class xit {
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
    XCreateProcess,
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
    XGetMappedFileName,
    XGetLogicalDriveStrings,
    XQueryDosDevice,
    XNoFound
  };
 public:
  using Result = unsigned long long;
  static_assert(8 == sizeof(Result), "8 != ull");
  static_assert(4 == sizeof(ERROR_ENUM), "4 != enum");
  static_assert(4 == sizeof(DWORD), "4 != dword");
//////////////////////////////////////////////////////////////// ERROR 相关。
 private:
  static inline Result XERROR(const ERROR_ENUM e, const DWORD ec) {
    // 不可写成一句，有溢出。
    Result res = e | 0x80000000;
    res <<= 32;
    return res | ec;
  }
  template<typename T>
  static Result XRETURN(const T v) {
    return (Result)v;
  }
 public:
  /// 获得 XIT_ERROR_ENUM 错误码。
  static inline ERROR_ENUM Error(const Result res) {
    return (ERROR_ENUM)((res >> 32) & 0x7FFFFFFF);
  }
  /// 获得 GetLastError 错误码。
  static inline DWORD ErrorEx(const Result res) {
    return (DWORD)(res & 0xFFFFFFFF);
  }
  /// 检测是否存在错误码。
  static inline bool IsOK(const Result res) {
    return 0 == (res & 0x8000000000000000);
  }
 public:
//////////////////////////////////////////////////////////////// 进程提权 。
  static inline Result UpperToken(HANDLE hProcess) {
    HANDLE TokenHandle;
    if (FALSE == OpenProcessToken(hProcess,
                                  TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                  &TokenHandle)) {
      return XERROR(XOpenProcessToken, GetLastError());
    }

    TOKEN_PRIVILEGES NewState;
    NewState.PrivilegeCount = 1;
    if (FALSE == LookupPrivilegeValue(nullptr,
                                      SE_DEBUG_NAME,
                                      &(NewState.Privileges[0].Luid))) {
      const auto ec = GetLastError();
      CloseHandle(TokenHandle);
      return XERROR(XLookupPrivilegeValue, ec);
    }

    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (FALSE == AdjustTokenPrivileges(TokenHandle,
                                       FALSE,
                                       &NewState,
                                       sizeof(NewState),
                                       nullptr,
                                       nullptr)) {
      const auto ec = GetLastError();
      CloseHandle(TokenHandle);
      return XERROR(XAdjustTokenPrivileges, ec);
    }
    CloseHandle(TokenHandle);
    return XRETURN(XSuccess);
  }
//////////////////////////////////////////////////////////////// PID 提取相关。
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
  static inline Result GetPID(LPCTSTR pid) {
    const auto PID = PickPID(pid);
    if (0 != PID) return XRETURN(PID);

    auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) {
      return XERROR(XCreateToolhelp32Snapshot, GetLastError());
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (FALSE == Process32First(hSnapshot, &pe32)) {
      const auto ec = GetLastError();
      CloseHandle(hSnapshot);
      return XERROR(XProcess32First, ec);
    }

    do {
      if (0 == _tcsicmp(pid, pe32.szExeFile)) {
        CloseHandle(hSnapshot);
        return XRETURN(pe32.th32ProcessID);
      }
    } while (FALSE != Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return XERROR(XGetPID, 0);
  }
//////////////////////////////////////////////////////////////// Module 提取相关。
  /// 指定 HMOUDLE 。成功则返回 HMOUDLE 。
  static inline Result GetModule(LPCTSTR hmod) {
  try {
    if (nullptr == hmod) return XERROR(XGetModule, 1);
    if (0 == _tcslen(hmod)) return XERROR(XGetModule, 2);
    auto str_end = (LPTSTR)hmod;
#ifdef _WIN64
    auto MOD = _tcstoull(hmod, &str_end, 16);
    if (ULLONG_MAX == MOD) return XERROR(XGetModule, 3);
#else
    auto MOD = _tcstoul(hmod, &str_end, 16);
    if (ULONG_MAX == MOD) return XERROR(XGetModule, 3);
#endif
    // 完全转换完成，并转换成功才行。
    if (TEXT('\0') != *str_end) return XERROR(XGetModule, 4);
    if (0 == MOD) return XERROR(XGetModule, 5);

    // 允许缺省 尾部 4 个 0 ，这里判断并自动补齐。
    if (MOD & 0xFFFF) MOD <<= 16;
    
    return XRETURN(MOD);
  } catch (...) {
    return XERROR(XGetModule, 6);
  }
  }
 public:
//////////////////////////////////////////////////////////////// Decode 。
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
//////////////////////////////////////////////////////////////// 文件加载 。
 public:
  /// 指定加载文件。成功则返回 HLOCAL。
  static inline Result LoadFile(LPCTSTR lpFileName, Decode_Function Decode = &NoDecode) {
    // 打开文件。
    auto hFile = CreateFile(lpFileName,
                            GENERIC_READ,
                            FILE_SHARE_READ,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_READONLY,
                            nullptr);
    if (INVALID_HANDLE_VALUE == hFile) {
      return XERROR(XCreateFile, GetLastError());
    }

    // 查询大小。
    LARGE_INTEGER FileSize;
    if (FALSE == GetFileSizeEx(hFile, &FileSize)) {
      const auto ec = GetLastError();
      CloseHandle(hFile);
      return XERROR(XGetFileSizeEx, ec);
    }
    if (0 != FileSize.HighPart) {
      CloseHandle(hFile);
      return XERROR(XLoadFile, 1);
    }

    // 申请内存。
    const auto uBytes = FileSize.LowPart;
    auto hMem = LocalAlloc(LMEM_MOVEABLE | LMEM_ZEROINIT, uBytes);
    if (nullptr == hMem) {
      const auto ec = GetLastError();
      CloseHandle(hFile);
      return XERROR(XLoadFileLocalAlloc, ec);
    }

    // 锁定内存。
    auto lpBuffer = LocalLock(hMem);
    if (nullptr == lpBuffer) {
      const auto ec = GetLastError();
      LocalFree(hMem);
      CloseHandle(hFile);
      return XERROR(XLoadFileLocalLock, ec);
    }

    // 读取文件。
    DWORD NumberOfBytesRead = 0;
    if (FALSE == ReadFile(hFile, lpBuffer, uBytes, &NumberOfBytesRead, nullptr)) {
      const auto ec = GetLastError();
      LocalUnlock(hMem);
      LocalFree(hMem);
      CloseHandle(hFile);
      return XERROR(XReadFile, ec);
    }

    // 释放文件句柄。
    CloseHandle(hFile);

    // 申请可写缓存。
    auto hMEM = LocalAlloc(LMEM_MOVEABLE | LMEM_ZEROINIT, uBytes);
    if (nullptr == hMEM) {
      const auto ec = GetLastError();
      LocalUnlock(hMem);
      LocalFree(hMem);
      return XERROR(XLocalAlloc, ec);
    }

    // 锁定内存。
    auto BIN = LocalLock(hMEM);
    if (nullptr == BIN) {
      const auto ec = GetLastError();
      LocalFree(hMEM);
      LocalUnlock(hMem);
      LocalFree(hMem);
      return XERROR(XLocalLock, ec);
    }
  
    const auto ok = Decode(BIN, lpBuffer, uBytes);
  
    LocalUnlock(hMem);
    LocalFree(hMem);
    LocalUnlock(hMEM);

    if (!ok) {
      LocalFree(hMEM);
      return XERROR(XDecode, 1);
    }

    return XRETURN(hMEM);
  }
//////////////////////////////////////////////////////////////// 资源加载 。
  /// 指定加载资源。成功则返回 HLOCAL。
  static inline Result LoadRes(HMODULE          hModule,
                               LPCTSTR          lpName,
                               LPCTSTR          lpType,
                               Decode_Function  Decode = &NoDecode) {
    // 加载资源。注意到：资源句柄无需释放。
    auto hResInfo = FindResource(hModule, lpName, lpType);
    if (nullptr == hResInfo) return XERROR(XFindResource, GetLastError());

    auto hResData = LoadResource(hModule, hResInfo);
    if (nullptr == hResData) return XERROR(XLoadResource, GetLastError());

    auto RES = LockResource(hResData);
    if (nullptr == RES) return XERROR(XLockResource, GetLastError());

    auto uBytes = SizeofResource(hModule, hResInfo);
    if (0 == uBytes) return XERROR(XSizeofResource, GetLastError());

    // 申请可写缓存。
    auto hMem = LocalAlloc(LMEM_MOVEABLE | LMEM_ZEROINIT, uBytes);
    if (nullptr == hMem) return XERROR(XLocalAlloc, GetLastError());

    auto BIN = LocalLock(hMem);
    if (nullptr == BIN) {
      const auto ec = GetLastError();
      LocalFree(hMem);
      return XERROR(XLocalLock, ec);
    }

    const auto ok = Decode(BIN, RES, uBytes);
    
    LocalUnlock(hMem);

    if (!ok) {
      LocalFree(hMem);
      return XERROR(XDecode, 2);
      }

    return XRETURN(hMem);
  }
//////////////////////////////////////////////////////////////// 平铺 。
  /// 平铺 DLL 。成功则返回 LPVOID 。
  static inline Result Mapping(HANDLE hProcess, HLOCAL hMem) {
    auto BIN = LocalLock(hMem);
    if (nullptr == BIN) return XERROR(XMappingLock, GetLastError());

    try {
      const auto& DosHeader = *(IMAGE_DOS_HEADER*)BIN;
      const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
      // 获取镜像大小。
      const auto SizeOfImage = NtHeaders.OptionalHeader.SizeOfImage;

      auto PE = VirtualAllocEx(hProcess,
                               nullptr,
                               SizeOfImage,
                               MEM_COMMIT,
                               PAGE_EXECUTE_READWRITE);
      if (nullptr == PE) {
        const auto ec = GetLastError();
        LocalUnlock(hMem);
        return XERROR(XVirtualAllocEx, ec);
      }

      // 所有 头 + 节表 头大小。
      const SIZE_T SizeOfHeaders = NtHeaders.OptionalHeader.SizeOfHeaders;

      // 写入所有 头 + 节表 头。
      if (FALSE == WriteProcessMemory(hProcess, PE, &DosHeader, SizeOfHeaders, nullptr)) {
        const auto ec = GetLastError();
        VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
        LocalUnlock(hMem);
        return XERROR(XMappingHeader, ec);
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
        auto dst = (void*)((size_t)PE + pSectionHeader->VirtualAddress);

        if (FALSE == WriteProcessMemory(hProcess, dst, src, pSectionHeader->SizeOfRawData, nullptr)) {
          const auto ec = GetLastError();
          VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
          LocalUnlock(hMem);
          return XERROR(XMappingSection, ec);
        }

        ++pSectionHeader;
      }

      LocalUnlock(hMem);
      return XRETURN(PE);
    } catch(...) {
      LocalUnlock(hMem);
      return XERROR(XMapping, 1);
    }
  }
 public:
//////////////////////////////////////////////////////////////// 打开进程 。
  /// 指定 PID 打开进程。成功则返回 HANDLE 。
  static inline Result OpenProcess(const DWORD PID) {
    auto hProcess = ::OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        TRUE, PID);
    if (nullptr == hProcess) return XERROR(XOpenProcess, GetLastError());
  
    return XRETURN(hProcess);
  }
  /// 自动识别为 PID 或 进程名，打开进程。成功则返回 HANDLE 。
  static inline Result OpenProcess(LPCTSTR info) {
    auto res = GetPID(info);
    if (!IsOK(res)) return res;
    
    const auto PID = (DWORD)res;
    return OpenProcess(PID);
  }
  /**
    指定 路径，创建进程。

    \param process_info 传入 PROCESS_INFORMATION 结构体指针 。不为 nullptr 时，则进挂起方式创建进程。
    \return 成功则返回 进程句柄 。
  */
  static inline Result CreateProcess(LPCTSTR path, PROCESS_INFORMATION* process_info) {
    const auto hold = nullptr != process_info;
    PROCESS_INFORMATION tpi;
    PROCESS_INFORMATION* const pi = hold ? process_info : &tpi;
    STARTUPINFO si = { sizeof(si) };

    if (FALSE == ::CreateProcess(path,
                                 nullptr,
                                 nullptr,
                                 nullptr,
                                 FALSE,
                                 hold ? CREATE_SUSPENDED : 0,
                                 nullptr,
                                 nullptr,
                                 &si,
                                 pi)) {
      return XERROR(XCreateProcess, GetLastError());
    }

    if (!hold) CloseHandle(pi->hThread);
    return XRETURN(pi->hProcess);
  }
//////////////////////////////////////////////////////////////// 远程线程 。
 public:
  /// 执行远程线程。成功则返回 线程 DWORD 。
  static inline Result RemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE shellcode, LPVOID lpParam) {
    auto hThread = CreateRemoteThread(hProcess, nullptr, 0, shellcode, lpParam, 0, nullptr);
    if (nullptr == hThread) return XERROR(XCreateRemoteThread, GetLastError());

    const auto wait = WaitForSingleObject(hThread, INFINITE);
    if (WAIT_TIMEOUT == wait) {
      const auto ec = GetLastError();
      TerminateThread(hThread, 0);
      CloseHandle(hThread);
      return XERROR(XWaitForSingleObject_timeout, ec);
      }
    if (WAIT_FAILED == wait ||  WAIT_OBJECT_0 != wait) {
      const auto ec = GetLastError();
      TerminateThread(hThread, 0);
      CloseHandle(hThread);
      return XERROR(XWaitForSingleObject_fail, ec);
    }

    DWORD tec;
    if (FALSE == GetExitCodeThread(hThread, &tec)) {
      const auto ec = GetLastError();
      TerminateThread(hThread, 0);
      CloseHandle(hThread);
      return XERROR(XGetExitCodeThread, ec);
    }

    CloseHandle(hThread);
    if (XSuccess != tec) return XERROR(XRemoteThread, tec);

    return XRETURN(tec);
  }
//////////////////////////////////////////////////////////////// 以下是 shellcode 部分。
//////////////////////////////////////////////////////////////// DoShellcode 。
 private:
  template<class T>
  static inline Result DoShellcode(HANDLE hProcess, LPTHREAD_START_ROUTINE shellcode, const size_t size, const T& st, const bool expand = false) {
    // 如果是当前进程，直接执行。而不再开远程线程。
    if (GetCurrentProcess() == hProcess) {
      struct EST {
        T st;
        Result res;
      };
      EST est = { st, XRETURN(XSuccess) };
      auto res = shellcode(&est);
      if (expand) return (XSuccess == est.res) ? XRETURN(XSuccess) : XERROR((xit::ERROR_ENUM)est.res, 0);
      return (XSuccess == res) ? XRETURN(XSuccess) : XERROR((xit::ERROR_ENUM)res, 0);
    }
    const auto alignsize = (size + 0x10) - (size % 0x10);
    const auto stsize = (sizeof(st) + 0x10) - (sizeof(st) % 0x10);
    const size_t Size = alignsize + stsize + sizeof(Result);

    Result res;

    auto Shellcode = VirtualAllocEx(hProcess, nullptr, Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (nullptr == Shellcode) return XERROR(XDoShellcodeNew, GetLastError());

    if (FALSE == WriteProcessMemory(hProcess, Shellcode, shellcode, size, nullptr)) {
      const auto ec = GetLastError();
      VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
      return XERROR(XWriteProcessMemory, ec);
    }

    auto pst = (LPVOID)((size_t)Shellcode + alignsize);
    if (FALSE == WriteProcessMemory(hProcess, pst, &st, sizeof(st), nullptr)) {
      const auto ec = GetLastError();
      VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
      return XERROR(XWriteProcessMemory, ec);
    }

    if (expand) {
      auto pex = (LPVOID)((size_t)Shellcode + alignsize + stsize);
      res = XRETURN(XSuccess);
      if (FALSE == WriteProcessMemory(hProcess, pex, &res, sizeof(res), nullptr)) {
        const auto ec = GetLastError();
        VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
        return XERROR(XWriteProcessMemory, ec);
      }
    }
    
    res = RemoteThread(hProcess, (LPTHREAD_START_ROUTINE)Shellcode, pst);
    if (!IsOK(res)) {
      VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
      return res;
    }
    auto tec = (DWORD)res;
    
    if (expand) {
      auto pex = (LPVOID)((size_t)Shellcode + alignsize + stsize);
      if (FALSE == ReadProcessMemory(hProcess, pex, &res, sizeof(res), nullptr)) {
        const auto ec = GetLastError();
        VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
        return XERROR(XReadProcessMemory, ec);
      }

      VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
      return res;
    }

    VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
    return XRETURN(tec);
  }
//////////////////////////////////////////////////////////////// 重定位。
  /*
    重定位表的结构：
      DWORD sectionAddress
      DWORD size  // 包括本节需要重定位的数据

    例如 1000 节 需要修正 5 个重定位数据的话，重定位表的数据是
    00 10 00 00   14 00 00 00      xxxx xxxx xxxx xxxx xxxx 0000
    -----------   -----------      ----
    给出节的偏移  总尺寸=8+6*2     需要修正的地址           用于对齐4字节

    重定位表是若干个相连，如果 address 和 size 都是 0 ， 表示结束。
    需要修正的地址是 12 位的，高 4 位是形态字，intel cpu下是 3 。
    
    假设 Base 是 0x600000 ，而文件中设置的缺省 ImageBase 是 0x400000 ，则修正偏移量就是 0x200000 。
    注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址。
  */
  struct RelocationST {
    LPVOID PE;
    LPVOID Base;
  };
  static inline DWORD WINAPI Relocation(LPVOID lpParam) {
    const auto& st = *(const RelocationST*)lpParam;

    const auto& DosHeader = *(const IMAGE_DOS_HEADER*)st.PE;
    const auto& NtHeaders = *(const IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);

    auto& dir = NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    auto pLoc = (PIMAGE_BASE_RELOCATION)((size_t)&DosHeader + dir.VirtualAddress);
    
    const auto dir_end = (size_t)&DosHeader + dir.VirtualAddress + dir.Size;

    // 是否有重定位表。
    if ((void*)pLoc == (void*)&DosHeader) return XSuccess;

    // 计算修正值。
    const size_t Delta = (size_t)st.Base - NtHeaders.OptionalHeader.ImageBase;

    // 扫描重定位表。
    while (0 != (pLoc->VirtualAddress + pLoc->SizeOfBlock)) {
      auto pLocData = (const WORD*)((size_t)pLoc + sizeof(IMAGE_BASE_RELOCATION));

      // 计算本节需要修正的重定位项（地址）的数目。
      size_t nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

      for (size_t i = 0; i < nNumberOfReloc; ++i) {
        // 每个 WORD 由两部分组成。高 4 位指出了重定位的类型，WINNT.H 中的一系列 IMAGE_REL_BASED_xxx 定义了重定位类型的取值。
        // 低 12 位是相对于 VirtualAddress 域的偏移，指出了必须进行重定位的位置。
#ifdef _WIN64
        const WORD Flag = 0xA000;
        // 对于 IA-64 的可执行文件，重定位似乎总是 IMAGE_REL_BASED_DIR64 类型的。
#else
        const WORD Flag = 0x3000;
        // 对于 x86 的可执行文件，所有的基址重定位都是 IMAGE_REL_BASED_HIGHLOW 类型的。
#endif
        if (Flag != (pLocData[i] & 0xF000)) continue;

        // 需要修正。
        auto& Address = *(size_t*)((size_t)&DosHeader + pLoc->VirtualAddress + (pLocData[i] & 0xFFF));
        Address += Delta;
      }
      
      pLoc = (PIMAGE_BASE_RELOCATION)((size_t)pLoc + pLoc->SizeOfBlock);
      // 有时重定位表是最后一个 section ，这里要判定，否则会非法访问。
      if ((size_t)(pLoc + sizeof(IMAGE_BASE_RELOCATION)) >= dir_end) break;
    }

    return XSuccess;
  }
  static inline auto RelocationEnd() { return &Relocation; }
//////////////////////////////////////////////////////////////// 导入表修正。
  struct ImportTableST {
    LPVOID PE;
    decltype(&LoadLibraryA) LoadLibraryA;
    decltype(&GetProcAddress) GetProcAddress;
  };
  static inline DWORD WINAPI ImportTable(LPVOID lpParam) {
    const auto& st = *(const ImportTableST*)lpParam;

    const auto& DosHeader = *(const IMAGE_DOS_HEADER*)st.PE;
    const auto& NtHeaders = *(const IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    const auto itva = NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (0 == itva) return XSuccess;

    auto pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((size_t)&DosHeader + itva);

    for (; 0 != pImportTable->OriginalFirstThunk; ++pImportTable) {
      // 获取导入表中 DLL 名称并加载。
      auto pDllName = (const char*)((size_t)&DosHeader + pImportTable->Name);
      auto hDll = st.LoadLibraryA(pDllName);
      if (nullptr == hDll) return XImportDLL;

      // 获取 OriginalFirstThunk 以及对应的导入函数名称表首地址。
      auto lpImportNameArray = (PIMAGE_THUNK_DATA)((size_t)&DosHeader + pImportTable->OriginalFirstThunk);

      // 获取 FirstThunk 以及对应的导入函数地址表首地址。
      auto lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((size_t)&DosHeader + pImportTable->FirstThunk);

      for (size_t i = 0; 0 != lpImportNameArray[i].u1.AddressOfData; ++i) {
        // 获取IMAGE_IMPORT_BY_NAME结构
        auto lpImportByName = (PIMAGE_IMPORT_BY_NAME)((size_t)&DosHeader + lpImportNameArray[i].u1.AddressOfData);

        // 判断导出函数是序号导出还是函数名称导出。
        // 当 IMAGE_THUNK_DATA 值的最高位为 1 时，表示函数以序号方式输入，这时，低位被看做是一个函数序号。
        const auto Flag = (size_t)0x1 << (sizeof(size_t) * 8 - 1);
        auto FuncAddr = st.GetProcAddress(
            hDll,
            (Flag & lpImportNameArray[i].u1.Ordinal) ?
              (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF) :
              (LPCSTR)lpImportByName->Name);

        // 注意此处的函数地址表的赋值，要对照PE格式进行装载。
        lpImportFuncAddrArray[i].u1.Function = (size_t)FuncAddr;
      }
    }
    return XSuccess;
  }
  static inline auto ImportTableEnd() { return &ImportTable; }
//////////////////////////////////////////////////////////////// 基址修正。
  static inline DWORD WINAPI SetImageBase(LPVOID lpParam) {
    const auto& DosHeader = **(IMAGE_DOS_HEADER**)lpParam;
    const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);

    const auto offset = (size_t)&(NtHeaders.OptionalHeader.ImageBase) - (size_t)&DosHeader;

    void** pImageBase = (void**)((size_t)&DosHeader + offset);
    void* ImageBase = (void*)&DosHeader;

    *pImageBase = ImageBase;

    return XSuccess;
  }
  static inline auto SetImageBaseEnd() { return &SetImageBase; }
//////////////////////////////////////////////////////////////// TLS 初始化。
  struct ExecuteTLSST {
    LPVOID PE;
    DWORD dwReason;
  };
  static inline DWORD WINAPI ExecuteTLS(LPVOID lpParam) {
    const auto& st = *(const ExecuteTLSST*)lpParam;

    const auto& DosHeader = *(IMAGE_DOS_HEADER*)st.PE;
    const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);

    auto& TLSDirectory = *(IMAGE_DATA_DIRECTORY*)&NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (0 == TLSDirectory.VirtualAddress)  return XSuccess;

    auto& tls = *(IMAGE_TLS_DIRECTORY*)((size_t)&DosHeader + TLSDirectory.VirtualAddress);

    auto callback = (PIMAGE_TLS_CALLBACK*)tls.AddressOfCallBacks;
    if (0 == callback) return XSuccess;

    for (; *callback; ++callback) {
      (*callback)((LPVOID)&DosHeader, st.dwReason, nullptr);
    }

    return XSuccess;
  }
  static inline auto ExecuteTLSEnd() { return &ExecuteTLS; }
//////////////////////////////////////////////////////////////// 运行入口。
  struct ExecuteDllMainST {
    LPVOID PE;
    DWORD dwReason;
  };
  static inline DWORD WINAPI ExecuteDllMain(LPVOID lpParam) {
    const auto& st = *(const ExecuteDllMainST*)lpParam;

    const IMAGE_DOS_HEADER& DosHeader = *(IMAGE_DOS_HEADER*)st.PE;
    const IMAGE_NT_HEADERS& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);

    using DllMainFunction = BOOL(WINAPI*)(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved);

    auto DllMain = (DllMainFunction)((size_t)&DosHeader + NtHeaders.OptionalHeader.AddressOfEntryPoint);
    DllMain((HINSTANCE)&DosHeader, st.dwReason, nullptr);

    return XSuccess;
  }
  static inline auto ExecuteDllMainEnd() { return &ExecuteDllMain; }
//////////////////////////////////////////////////////////////// 卸载导入 DLL 。
  struct UnloadImportST {
    LPVOID PE;
    decltype(&GetModuleHandleA) GetModuleHandleA;
    decltype(&FreeLibrary) FreeLibrary;
  };
  static inline DWORD WINAPI UnloadImport(LPVOID lpParam) {
    const auto& st = *(const UnloadImportST*)lpParam;

    const auto& DosHeader = *(IMAGE_DOS_HEADER*)st.PE;
    const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((size_t)&DosHeader +
        NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; 0 != pImportTable->OriginalFirstThunk; ++pImportTable) {
      LPCSTR pDllName = (LPCSTR)((size_t)&DosHeader + pImportTable->Name);
      HMODULE hLibModule = st.GetModuleHandleA(pDllName);
      if (NULL != hLibModule) st.FreeLibrary(hLibModule);
    }

    return XSuccess;
  }
  static inline auto UnloadImportEnd() { return &UnloadImport; }
//////////////////////////////////////////////////////////////// shellcode 部分结束。
//////////////////////////////////////////////////////////////// LoadDll 。
 public:
  /**
    【内核】指定加载 DLL 。

    \return 成功则返回 PE 。

    \note 注意：PE 需已平铺 。
  */
  static inline Result LoadDll(HANDLE hProcess, LPVOID PE) {
#define SCSET(func) &func, (size_t)&func##End - (size_t)&func

    // 重定位。注意：重定位之前不能填写加载基址。
    RelocationST rst = {PE, PE};
    auto res = DoShellcode(hProcess, SCSET(Relocation), rst);
    if (!IsOK(res)) return res;

    // 填写导入表。
    const ImportTableST itst = {PE, &LoadLibraryA, &GetProcAddress};
    res = DoShellcode(hProcess, SCSET(ImportTable), itst);
    if (!IsOK(res)) return res;

    // 填写文件加载基址。
    res = DoShellcode(hProcess, SCSET(SetImageBase), PE);
    if (!IsOK(res)) return res;

    // TLS
    const ExecuteTLSST etst = {PE, DLL_PROCESS_ATTACH};
    res = DoShellcode(hProcess, SCSET(ExecuteTLS), etst);
    if (!IsOK(res)) return res;

    // 运行入口函数。
    const ExecuteDllMainST edst = {PE, DLL_PROCESS_ATTACH};
    res = DoShellcode(hProcess, SCSET(ExecuteDllMain), edst);
    if (!IsOK(res)) return res;

#undef SCSET

    return XRETURN(PE);
  }
  /// 指定加载文件为 DLL 。成功则返回 LPVOID 。
  static inline Result LoadDll(HANDLE hProcess, LPCTSTR lpFileName, Decode_Function Decode = &NoDecode) {
    auto res = LoadFile(lpFileName, Decode);
    if (!IsOK(res))  return res;

    auto hMem = (HLOCAL)res;
    res = Mapping(hProcess, hMem);
    LocalFree(hMem);
    if (!IsOK(res)) return res;
    auto PE = (LPVOID)res;

    res = LoadDll(hProcess, PE);
    if (!IsOK(res)) VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);

    return res;
  }
  /**
    指定 PID 或 进程名，加载文件为 DLL 。成功则返回 LPVOID 。
    
    \warning 谨慎使用，因为 进程句柄在内部创建，操控性较差。
  */
  static inline Result LoadDll(LPCTSTR pid, LPCTSTR lpFileName, Decode_Function Decode = &NoDecode){
    auto res = OpenProcess(pid);
    if (!IsOK(res)) return res;
    auto hProcess = (HANDLE)res;

    res = LoadDll(hProcess, lpFileName, Decode);
    
    CloseHandle(hProcess);
    
    return res;
  }
  /// 指定加载资源为 DLL 。成功则返回 LPVOID 。
  static inline Result LoadDll(HANDLE           hProcess,
                               HMODULE          hModule,
                               LPCTSTR          lpName,
                               LPCTSTR          lpType,
                               Decode_Function  Decode = &NoDecode) {
    auto res = LoadRes(hModule, lpName, lpType, Decode);
    if (!IsOK(res)) return res;
    
    auto hMem = (HLOCAL)res;
    res = Mapping(hProcess, hMem);
    LocalFree(hMem);
    if (!IsOK(res)) return res;
    auto PE = (LPVOID)res;

    res = LoadDll(hProcess, PE);
    if (!IsOK(res)) VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);

    return res;
  }
  /**
    指定加载资源为 DLL 。成功则返回 LPVOID 。
    
    \warning 谨慎使用，因为 进程句柄在内部创建，操控性较差。
  */
  static inline Result LoadDll(LPCTSTR          pid,
                               HMODULE          hModule,
                               LPCTSTR          lpName,
                               LPCTSTR          lpType,
                               Decode_Function  Decode = &NoDecode) {
    auto res = OpenProcess(pid);
    if (!IsOK(res)) return res;
    auto hProcess = (HANDLE)res;
    
    res = LoadDll(hProcess, hModule, lpName, lpType, Decode);
    
    CloseHandle(hProcess);
    
    return res;
  }
//////////////////////////////////////////////////////////////// UnloadDll 。
 public:
  struct UnloadDllST {
    Result tls;
    Result main;
    Result import;
    Result ex;
  };
  /// 指定卸载 DLL 。
  static inline UnloadDllST UnloadDll(HANDLE hProcess, LPVOID PE, const bool release_pe = true) {
    UnloadDllST st;
    st.ex = XRETURN(XSuccess);

  #define SCSET(func) &func, (size_t)&func##End - (size_t)&func

    // TLS
    const ExecuteTLSST etst = {PE, DLL_PROCESS_DETACH};
    st.tls = DoShellcode(hProcess, SCSET(ExecuteTLS), etst);

    // 运行入口函数。
    const ExecuteDllMainST edst = {PE, DLL_PROCESS_DETACH};
    st.main = DoShellcode(hProcess, SCSET(ExecuteDllMain), edst);

    // 卸载导入 DLL 。
    const UnloadImportST uist = {PE, &GetModuleHandleA, &FreeLibrary};
    st.import = DoShellcode(hProcess, SCSET(UnloadImport), uist);

  #undef SCSET

    if (release_pe) VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
    return st;
  }
  /**
    指定卸载 DLL 。
    
    \warning 谨慎使用，因为 进程句柄在内部创建，操控性较差。
  */
  static inline UnloadDllST UnloadDll(LPCTSTR pid, LPVOID PE) {
    UnloadDllST st;
    st.ex = OpenProcess(pid);
    if (!IsOK(st.ex)) return st;
    auto hProcess = (HANDLE)st.ex;

    st = UnloadDll(hProcess, PE, true);
    CloseHandle(hProcess);
    return st;
  }
//////////////////////////////////////////////////////////////// 本地导出函数。
 public:
  /// 本地查找指定模块的导出函数。
  static inline Result LocalDllProcAddr(LPVOID PE, LPCSTR lpProcName, const bool fuzzy = false) {
  try {
    const auto& DosHeader = *(const IMAGE_DOS_HEADER*)PE;
    const auto& NtHeaders = *(const IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    const auto& ExportEntry = *(const IMAGE_DATA_DIRECTORY*)&NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (0 == ExportEntry.Size) return XERROR(XNoExport, 1);
    
    const auto& ExportTable = *(const IMAGE_EXPORT_DIRECTORY*)((size_t)&DosHeader + ExportEntry.VirtualAddress);
    auto pAddressOfFunction = (const DWORD*)((size_t)&DosHeader + ExportTable.AddressOfFunctions);
    
    LPVOID addr = NULL;

    const auto Name = (DWORD)(size_t)lpProcName;
    if (0 == (Name & 0xFFFF0000)) {
      // 序号查找。
      const auto dwBase = ExportTable.Base;
      if(Name < dwBase) return XERROR(XIndex, 1);
      if(Name > dwBase + ExportTable.NumberOfFunctions - 1) return XERROR(XIndex, 2);
      addr = (LPVOID)((size_t)&DosHeader + pAddressOfFunction[Name - dwBase]);
    } else {
      auto pAddressOfName = (const DWORD*)((size_t)&DosHeader + ExportTable.AddressOfNames);
      auto pAddressOfNameOrdinals = (const WORD*)((size_t)&DosHeader + ExportTable.AddressOfNameOrdinals);

      for (size_t i = 0; i < (size_t)ExportTable.NumberOfNames; ++i) {
        auto name = (LPCSTR)((size_t)&DosHeader + pAddressOfName[i]);
        if (fuzzy) {
          if (nullptr != strstr(name, lpProcName)) {
            addr = (LPVOID)((size_t)&DosHeader + pAddressOfFunction[pAddressOfNameOrdinals[i]]);
            break;
          }
        } else {
          if (0 == strcmp(name, lpProcName)) {
            addr = (LPVOID)((size_t)&DosHeader + pAddressOfFunction[pAddressOfNameOrdinals[i]]);
            break;
          }
        }
      }
    }
    
    if (NULL == addr) return XERROR(XNoFind, 1);

    // 判断是否合法。
    if ((size_t)addr < (size_t)ExportEntry.VirtualAddress) return XRETURN(addr);
    if ((size_t)addr > ((size_t)ExportEntry.VirtualAddress + ExportEntry.Size)) return XRETURN(addr);

    CHAR reload[MAX_PATH] = {'\0'};
    lstrcpyA(reload, (LPCSTR)addr);

    LPSTR p = strchr(reload, '.');
    if (NULL == p) return XERROR(XNoMod, 1);
    *p = '\0';
    ++p;

    HMODULE hMod = GetModuleHandleA(reload);
    if (NULL == hMod)  return XERROR(XGetModuleHandleA, 0);

    FARPROC func = GetProcAddress(hMod, p);
    if (NULL == func)  return XERROR(XGetProcAddress, 0);

    return XRETURN(func);
  } catch(...) {
    return XERROR(XLocalDllProcAddr, 0);
  }
  }
  /// 指定 DLL 模块，镜像之。
  static inline Result DLLMirror(HANDLE hProcess, HMODULE hModule) {
    /*
      注意到：
      GetModuleFileName 与 CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE) 都不能正确获取模块路径。其返回 system32 路径，但实际应该是 sysWOW64 。
    */
    TCHAR Filename[MAX_PATH];
    if (0 == GetMappedFileName(hProcess, hModule, Filename, _countof(Filename))) {
      return XERROR(XGetMappedFileName, GetLastError());
    }

    TCHAR drivers[512];
    drivers[0] = TEXT('\0');
    const auto dl = GetLogicalDriveStrings(_countof(drivers), drivers);
    if (0 == dl) return XERROR(XGetLogicalDriveStrings, GetLastError());
    if (_countof(drivers) <= dl) return XERROR(XGetLogicalDriveStrings, GetLastError());

    TCHAR dev[MAX_PATH];
    TCHAR driver[3] = TEXT(" :");
    bool found = false;
    TCHAR* p = drivers;
    do {
      *driver = *p;
      // 注意到 QueryDosDevice 的返回长度不能用。
      if (0 == QueryDosDevice(driver, dev, _countof(dev))) {
        return XERROR(XQueryDosDevice, GetLastError());
      }
      const auto devlen = _tcslen(dev);
      if (0 == _tcsnicmp(Filename, dev, devlen) && TEXT('\\') == Filename[devlen]) {
        found = true;
        _tcscpy_s(Filename, driver);
        _tcscat_s(Filename, &Filename[devlen]);
        break;
      }
      while (*p++);
    } while (!found && *p);
    
    if(!found) return XERROR(XNoFound, 0);

    auto ret = LoadFile(Filename);
    if (!IsOK(ret)) return ret;

    auto hMem = (HLOCAL)ret;
    ret = Mapping(hProcess, hMem);
    LocalFree(hMem);
    if (!IsOK(ret)) return ret;
    auto PE = (LPVOID)ret;
    
#define SCSET(func) &func, (size_t)&func##End - (size_t)&func
    // 重定位。注意：重定位之前不能填写加载基址。
    RelocationST rst = {PE, hModule};
    auto res = DoShellcode(hProcess, SCSET(Relocation), rst);
    if (!IsOK(res)) {
      VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
      return res;
    }

    // 填写导入表。
    const ImportTableST itst = {PE, &LoadLibraryA, &GetProcAddress};
    res = DoShellcode(hProcess, SCSET(ImportTable), itst);
    if (!IsOK(res)) {
      VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
      return res;
    }

    // 填写文件加载基址。
    res = DoShellcode(hProcess, SCSET(SetImageBase), PE);
    if (!IsOK(res)) {
      VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
      return res;
    }
#undef SCSET

    return XRETURN(PE);
  }
//////////////////////////////////////////////////////////////// 远程导出函数。
 private:
  struct RemoteDllProcAddrST {
    LPVOID PE;
    bool fuzzy;
    decltype(&GetModuleHandleA) GetModuleHandleA;
    decltype(&GetProcAddress) GetProcAddress;
    LPCSTR lpProcName;
    CHAR ProcName[MAX_PATH];
  };
  static inline DWORD WINAPI RemoteDllProcAddrShellCode(LPVOID lpParam) {
    const auto& st = *(const RemoteDllProcAddrST*)lpParam;

    const auto stsize = (sizeof(st) + 0x10) - (sizeof(st) % 0x10);
    auto& res = *(Result*)((size_t)lpParam + stsize);

    const auto& DosHeader = *(const IMAGE_DOS_HEADER*)st.PE;
    const auto& NtHeaders = *(const IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    const auto& ExportEntry = *(const IMAGE_DATA_DIRECTORY*)&NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    
    if (0 == ExportEntry.Size) return XNoExport;
    
    const auto& ExportTable = *(const IMAGE_EXPORT_DIRECTORY*)((size_t)&DosHeader + ExportEntry.VirtualAddress);
    auto pAddressOfFunction = (const DWORD*)((size_t)&DosHeader + ExportTable.AddressOfFunctions);
    
    LPVOID addr = NULL;

    const auto Name = (DWORD)(size_t)st.lpProcName;
    if (0 == (Name & 0xFFFF0000)) {
      // 序号查找。
      const auto dwBase = ExportTable.Base;
      if(Name < dwBase) return XIndex;
      if(Name > dwBase + ExportTable.NumberOfFunctions - 1) return XIndex;
      addr = (LPVOID)((size_t)&DosHeader + pAddressOfFunction[Name - dwBase]);
    } else {
      auto pAddressOfName = (const DWORD*)((size_t)&DosHeader + ExportTable.AddressOfNames);
      auto pAddressOfNameOrdinals = (const WORD*)((size_t)&DosHeader + ExportTable.AddressOfNameOrdinals);

      for (size_t i = 0; i < (size_t)ExportTable.NumberOfNames; ++i) {
        auto name = (LPCSTR)((size_t)&DosHeader + pAddressOfName[i]);
        if (st.fuzzy) {
          bool ok = false;
          for (size_t x = 0; '\0' != name[x]; ++x) {
            if ('\0' == st.ProcName[0]) break;
            for (size_t k = 0; name[x + k] == st.ProcName[k]; ++k) {
              if ('\0' == st.ProcName[k + 1]) {
                ok = true;
                break;
              }
            }
            if (ok) break;
          }

          if (ok) {
            addr = (LPVOID)((size_t)&DosHeader + pAddressOfFunction[pAddressOfNameOrdinals[i]]);
            break;
          }
        } else {
          bool ok = false;
          for (size_t x = 0; !ok; ++x) {
            if (name[x] != st.ProcName[x]) break;
            if ('\0' == name[x]) {
              ok = true;
              break;
            }
          }

          if (ok) {
            addr = (LPVOID)((size_t)&DosHeader + pAddressOfFunction[pAddressOfNameOrdinals[i]]);
            break;
          }
        }
      }
    }
    
    if (NULL == addr) return XNoFind;

    // 判断是否合法。
    if ((size_t)addr < (size_t)ExportEntry.VirtualAddress) {
      res = (Result)addr;
      return XSuccess;
    }
    if ((size_t)addr > ((size_t)ExportEntry.VirtualAddress + ExportEntry.Size)) {
      res = (Result)addr;
      return XSuccess;
    }

    CHAR reload[MAX_PATH] = {'\0'};
    for (size_t i = 0; '\0' != *(CHAR*)((size_t)addr + i); ++i) {
      reload[i] = *(CHAR*)((size_t)addr + i);
    }

    LPSTR p = nullptr;
    for (size_t i = 0; '\0' != reload[i]; ++i) {
      if ('.' == reload[i]) {
        p = &reload[i];
        break;
      }
    }
    if (nullptr == p) return XNoMod;

    *p = '\0';
    ++p;

    HMODULE hMod = st.GetModuleHandleA(reload);
    if (NULL == hMod)  return XGetModuleHandleA;

    FARPROC func = st.GetProcAddress(hMod, p);
    if (NULL == func)  return XGetProcAddress;

    res = (Result)func;
    return XSuccess;
  }
  static inline auto RemoteDllProcAddrShellCodeEnd() { return &RemoteDllProcAddrShellCode; }
 public:
  static inline Result RemoteDllProcAddr(HANDLE hProcess, LPVOID PE, LPCSTR lpProcName, const bool fuzzy = false) {
    RemoteDllProcAddrST st;
    st.PE = PE;
    st.fuzzy = fuzzy;
    st.GetModuleHandleA = &GetModuleHandleA;
    st.GetProcAddress = &GetProcAddress;
    st.lpProcName = lpProcName;

    const auto Name = (DWORD)(size_t)st.lpProcName;
    if (0 != (Name & 0xFFFF0000)) lstrcpyA(&st.ProcName[0], lpProcName);

  #define SCSET(func) &func, (size_t)&func##End - (size_t)&func
    return DoShellcode(hProcess, SCSET(RemoteDllProcAddrShellCode), st, true);
  #undef SCSET
  }

};

#endif  //_xit_H_