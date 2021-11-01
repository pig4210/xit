#include "xit.h"

#include <limits.h>
#include <wchar.h>

#include <Tlhelp32.h>

namespace xit
  {
////////////////////////////////////////////////////////////////
class xhandle
  {
  public:
    xhandle(HANDLE h = nullptr)
      : hHandle(h), hold(false)
      {
      }
    void close()
      {
      if(nullptr == hHandle) return;
      if(INVALID_HANDLE_VALUE == hHandle) return;
      if(hold) return;
      CloseHandle(hHandle);
      hHandle = nullptr;
      }
    ~xhandle()
      {
      close();
      }
  public:
    xhandle(const xhandle&) = delete;
    xhandle& operator=(const xhandle&) = delete;
  public:
    operator HANDLE() const
      {
      return hHandle;
      }
    HANDLE* operator &()
      {
      return &hHandle;
      }
    HANDLE holdit()
      {
      hold = true;
      return hHandle;
      }
  private:
    HANDLE hHandle;
    bool hold;
  };

class xmem
  {
  public:
    xmem(const SIZE_T uBytes)
      : hMem(LocalAlloc(LMEM_MOVEABLE | LMEM_ZEROINIT, uBytes)),
      hold(false), locked(false)
      {
      }
    xmem(HLOCAL h)
      : hMem(h), hold(true), locked(false)
      {
      }
    ~xmem()
      {
      if(nullptr == hMem) return;
      if(locked)
        {
        LocalUnlock(hMem);
        locked = false;
        }
      if(hold) return;
      LocalFree(hMem);
      hMem = nullptr;
      }
  public:
    xmem(const xmem&) = delete;
    xmem& operator=(const xmem&) = delete;
  public:
    operator HLOCAL() const
      {
      return hMem;
      }
    LPVOID lock()
      {
      locked = true;
      return LocalLock(hMem);
      }
    HLOCAL holdit()
      {
      hold = true;
      return hMem;
      }
  private:
    HLOCAL hMem;
    bool hold;
    bool locked;
  };

class xprocmem
  {
  public:
    xprocmem(HANDLE h, const SIZE_T dwSize)
      : hProcess(h), hold(false),
      lpAddress(VirtualAllocEx(h, nullptr, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE))
      {
      }
    xprocmem(HANDLE h, LPVOID p)
      : hProcess(h), hold(true), lpAddress(p)
      {
      }
    ~xprocmem()
      {
      if(nullptr == lpAddress) return;
      if(hold) return;
      VirtualFreeEx(hProcess, lpAddress, 0, MEM_RELEASE);
      lpAddress = nullptr;
      }
  public:
    xprocmem(const xprocmem&) = delete;
    xprocmem& operator=(const xprocmem&) = delete;
  public:
    operator LPVOID() const
      {
      return lpAddress;
      }
    LPVOID holdit()
      {
      hold = true;
      return lpAddress;
      }
  private:
    HANDLE hProcess;
    LPVOID lpAddress;
    bool hold;
  };

class xthread
  {
  public:
    xthread(HANDLE hProcess, LPTHREAD_START_ROUTINE shellcode, LPVOID lpParam)
      : hThread(CreateRemoteThread(hProcess, nullptr, 0, shellcode, lpParam, 0, nullptr))
      {
      }
    void close()
      {
      if(nullptr == hThread) return;
      if(INVALID_HANDLE_VALUE == hThread) return;
      TerminateThread(hThread, 0);
      CloseHandle(hThread);
      hThread = nullptr;
      }
    ~xthread()
      {
      close();
      }
  public:
    xthread(const xthread&) = delete;
    xthread& operator=(const xthread&) = delete;
  public:
    operator HANDLE() const
      {
      return hThread;
      }
  private:
    HANDLE hThread;
  };

////////////////////////////////////////////////////////////////
Result::Result(const ERROR_ENUM e) : _v(0)
  {
  _x = XSuccess != e;
  _e = e;
  _ec = XSuccess == e ? 0 : GetLastError();
  }

ERROR_ENUM Result::Error() const
  {
  return _e;
  }

DWORD Result::ErrorCode() const
  {
  return _ec;
  }

bool Result::IsOK() const
  {
  return 0 == _x;
  }

Result::operator bool() const
  {
  return IsOK();
  }

////////////////////////////////////////////////////////////////
Result UpperToken(HANDLE hProcess)
  {
  xhandle TokenHandle;
  if(FALSE == OpenProcessToken(hProcess,
                               TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                               &TokenHandle))
    return XOpenProcessToken;

  TOKEN_PRIVILEGES NewState;
  NewState.PrivilegeCount = 1;
  if(FALSE == LookupPrivilegeValue(nullptr,
                                   SE_DEBUG_NAME,
                                   &(NewState.Privileges[0].Luid)))
    return XLookupPrivilegeValue;

  NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  if(FALSE == AdjustTokenPrivileges(TokenHandle,
                                    FALSE,
                                    &NewState,
                                    sizeof(NewState),
                                    nullptr,
                                    nullptr))
    return XAdjustTokenPrivileges;
  
  return XSuccess;
  }

////////////////////////////////////////////////////////////////
static DWORD PickPID(LPCTSTR pid)
  {
  try
    {
    auto str_end = (LPTSTR)pid;

#ifdef UNICODE
    const unsigned long PID = wcstoul(pid, &str_end, 16);
#else
    const unsigned long PID = strtoul(pid, &str_end, 16);
#endif
    // 完全转换完成，并转换成功才行。
    if(TEXT('\0') != *str_end) return 0;
    if(ULONG_MAX != PID) return 0;
    return PID;
    }
  catch(...)
    {
    return 0;
    }
  }

Result GetPID(LPCTSTR pid)
  {
  const auto PID = PickPID(pid);
  if(0 != PID) return PID;

  const xhandle hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if(INVALID_HANDLE_VALUE == hSnapshot)
    return XCreateToolhelp32Snapshot;
  
  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(pe);
  if(FALSE == Process32First(hSnapshot, &pe)) return XProcess32First;

  do
    {
#ifdef UNICODE
    if(0 == _wcsicmp(pid, pe.szExeFile))
#else
    if(0 == _stricmp(pid, pe.szExeFile))
#endif
      return pe.th32ProcessID;
    }while(FALSE != Process32Next(hSnapshot, &pe));

  return XGetPID;
  }

////////////////////////////////////////////////////////////////
Result GetModule(LPCTSTR hmod)
  {
  try
    {
    auto str_end = (LPTSTR)hmod;

#ifdef _WIN64
    unsigned long long MOD =
  #ifdef UNICODE
    wcstoull(hmod, &str_end, 16);
  #else
    strtoull(hmod, &str_end, 16);
  #endif
    if(ULLONG_MAX != MOD) return XGetModule_MAX;
#else
    unsigned long MOD =
  #ifdef UNICODE
    wcstoul(hmod, &str_end, 16);
  #else
    strtoul(hmod, &str_end, 16);
  #endif
    if(ULONG_MAX != MOD) return XGetModule_MAX;
#endif
    // 完全转换完成，并转换成功才行。
    if(TEXT('\0') != *str_end) return XGetModule_FAIL;
    if(0 == MOD) return XGetModule_NULL;
    // 允许缺省 尾部 4 个 0 ，这里判断并自动补齐。
    if(MOD & 0xFFFF) MOD <<= 16;
    return MOD;
    }
  catch(...)
    {
    return XGetModule;
    }
  }

////////////////////////////////////////////////////////////////
bool NoDecode(LPVOID BIN, LPVOID SRC, const size_t size)
  {
  try
    {
    CopyMemory(BIN, SRC, size);
    return true;
    }
  catch(...)
    {
    return false;
    }
  }

////////////////////////////////////////////////////////////////
Result LoadFile(LPCTSTR lpFileName, Decode_Function Decode)
  {
  // 打开文件。
  xhandle hFile = CreateFileW(
    lpFileName,
    GENERIC_READ,
    FILE_SHARE_READ,
    nullptr,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_READONLY,
    nullptr);
  if(INVALID_HANDLE_VALUE == hFile) return XCreateFile;

  // 查询大小。
  LARGE_INTEGER FileSize;
  if(FALSE == GetFileSizeEx(hFile, &FileSize))
    return XGetFileSizeEx;

  if(0 != FileSize.HighPart) return XLoadFileMAX;

  // 申请内存。
  const auto uBytes = FileSize.LowPart;
  xmem hMem(uBytes);
  if(nullptr == hMem) return XLoadFileLocalAlloc;

  // 锁定内存。
  auto lpBuffer = hMem.lock();
  if(nullptr == lpBuffer) return XLoadFileLocalLock;

  // 读取文件。
  DWORD NumberOfBytesRead = 0;
  if(FALSE == ReadFile(hFile, lpBuffer, uBytes, &NumberOfBytesRead, nullptr))
    return XReadFile;

  // 释放文件句柄。
  hFile.close();

  // 申请可写缓存。
  xmem hMEM(uBytes);
  if(nullptr == hMEM) return XLocalAlloc;

  // 锁定内存。
  auto BIN = hMEM.lock();
  if(nullptr == BIN) return XLocalLock;
  
  const auto ok = Decode(BIN, lpBuffer, uBytes);

  if(!ok) return XDecode;
  
  return hMEM.holdit();
  }
////////////////////////////////////////////////////////////////
Result LoadRes(HMODULE hModule, LPCTSTR lpName, LPCTSTR lpType, Decode_Function Decode)
  {
  // 加载资源。注意到：资源句柄无需释放。
  auto hResInfo = FindResource(hModule, lpName, lpType);
  if(nullptr == hResInfo) return XFindResource;

  auto hResData = LoadResource(hModule, hResInfo);
  if(nullptr == hResData) return XLoadResource;

  auto RES = LockResource(hResData);
  if(nullptr == RES) return XLockResource;

  auto uBytes = SizeofResource(hModule, hResInfo);
  if(0 == uBytes) return XSizeofResource;
  // 申请可写缓存。
  xmem hMem(uBytes);
  if(nullptr == hMem) return XLocalAlloc;

  auto BIN = hMem.lock();
  if(nullptr == BIN)  return XLocalLock;

  const auto ok = Decode(BIN, RES, uBytes);
  
  if(!ok) return XDecode;
  
  return hMem.holdit();
  }
////////////////////////////////////////////////////////////////
Result Mapping(HANDLE hProcess, HLOCAL hMem)
  {
  try
    {
    xmem Mem(hMem);
    auto BIN = Mem.lock();
    if(nullptr == BIN) return XMappingLock;

    const auto& DosHeader = *(IMAGE_DOS_HEADER*)BIN;
    const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    // 获取镜像大小。
    const auto SizeOfImage = NtHeaders.OptionalHeader.SizeOfImage;
    xprocmem PE(hProcess, SizeOfImage);
    if(nullptr == PE) return XVirtualAllocEx;

    // 所有 头 + 节表 头大小。
    const SIZE_T SizeOfHeaders = NtHeaders.OptionalHeader.SizeOfHeaders;
    // 写入所有 头 + 节表 头。
    if(FALSE == WriteProcessMemory(hProcess, PE, &DosHeader, SizeOfHeaders, nullptr))
      return XMappingHeader;

    // 节表数量。
    const size_t NumberOfSections = NtHeaders.FileHeader.NumberOfSections;
    // 获取第一个 节表头 的地址。
    auto pSectionHeader = (IMAGE_SECTION_HEADER*)((size_t)&NtHeaders + sizeof(NtHeaders));
    // 写入所有 节表。
    for(size_t i = 0; i < NumberOfSections; ++i)
      {
      if((0 == pSectionHeader->VirtualAddress) || (0 == pSectionHeader->SizeOfRawData))
          {
          ++pSectionHeader;
          continue;
          }
      auto src = (void*)((size_t)&DosHeader + pSectionHeader->PointerToRawData);
      auto dst = (void*)((size_t)(LPVOID)PE + pSectionHeader->VirtualAddress);
      if(FALSE == WriteProcessMemory(hProcess, dst, src, pSectionHeader->SizeOfRawData, nullptr))
        return XMappingSection;

      ++pSectionHeader;
      }
    return PE.holdit();
    }
  catch(...)
    {
    return XMapping;
    }
  }
////////////////////////////////////////////////////////////////
Result OpenProcess(const DWORD PID)
  {
  auto hProcess = ::OpenProcess(
    PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
    TRUE, PID);
  if(nullptr == hProcess) return XOpenProcess;
  return hProcess;
  }
Result OpenProcess(LPCTSTR pid)
  {
  auto res = GetPID(pid);
  if(!res) return res;
  const auto PID = (const DWORD)res;
  return OpenProcess(PID);
  }
////////////////////////////////////////////////////////////////
Result RemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE shellcode, LPVOID lpParam)
  {
  xthread hThread(hProcess, shellcode, lpParam);
  if(nullptr == hThread) return XCreateRemoteThread;

  const auto wait = WaitForSingleObject(hThread, INFINITE);
  if(WAIT_TIMEOUT == wait) return XWaitForSingleObject_timeout;

  if(WAIT_FAILED == wait ||  WAIT_OBJECT_0 != wait)
    return XWaitForSingleObject_fail;

  DWORD ec;
  if(FALSE == GetExitCodeThread(hThread, &ec))
    return XGetExitCodeThread;

  hThread.close();

  if(XSuccess != ec)
    {
    SetLastError(ec);
    return XRemoteThread;
    }

  return ec;
  }
////////////////////////////////////////////////////////////////
template<class T>
static Result DoShellcode(HANDLE hProcess, LPTHREAD_START_ROUTINE shellcode, const size_t size, const T& st, const bool expand = false)
  {
  const auto alignsize = (size + 0x10) - (size % 0x10);
  const auto stsize = (sizeof(st) + 0x10) - (sizeof(st) % 0x10);
  const size_t Size = alignsize + stsize + sizeof(Result);

  Result res;

  xprocmem Shellcode(hProcess, Size);
  if(nullptr == Shellcode) return XDoShellcodeNew;

  if(FALSE == WriteProcessMemory(hProcess, Shellcode, shellcode, size, nullptr))
    {
    const auto r = XERROR(XWriteProcessMemory);
    VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
    return r;
    }
  auto pst = (LPVOID)((size_t)Shellcode + alignsize);
  if(FALSE == WriteProcessMemory(hProcess, pst, &st, sizeof(st), nullptr))
    {
    const auto r = XERROR(XWriteProcessMemory);
    VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
    return r;
    }
  if(expand)
    {
    auto pex = (LPVOID)((size_t)Shellcode + alignsize + stsize);
    res = XRETURN(Success);
    if(FALSE == WriteProcessMemory(hProcess, pex, &res, sizeof(res), nullptr))
      {
      const auto r = XERROR(XWriteProcessMemory);
      VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
      return r;
      }
    }
  
  res = RemoteThread(hProcess, (LPTHREAD_START_ROUTINE)Shellcode, pst);
  if(!IsOK(res))
    {
    VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
    return res;
    }
  auto ec = (DWORD)res;
  
  if(expand)
    {
    auto pex = (LPVOID)((size_t)Shellcode + alignsize + stsize);
    if(FALSE == ReadProcessMemory(hProcess, pex, &res, sizeof(res), nullptr))
      {
      const auto r = XERROR(XReadProcessMemory);
      VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
      return r;
      }
    VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
    return res;
    }
  VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
  return XRETURN(ec);
  }
////////////////////////////////////////////////////////////////
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
static DWORD WINAPI Relocation(LPVOID lpParam)
  {
  const auto& DosHeader = **(const IMAGE_DOS_HEADER**)lpParam;
  const auto& NtHeaders = *(const IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
  auto pLoc = (PIMAGE_BASE_RELOCATION)((size_t)&DosHeader + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
  // 是否有重定位表。
  if((void*)pLoc == (void*)&DosHeader) return Success;
  // 计算修正值。
  const size_t Delta = (size_t)&DosHeader - NtHeaders.OptionalHeader.ImageBase;
  // 扫描重定位表。
  while(0 != (pLoc->VirtualAddress + pLoc->SizeOfBlock))
    {
    auto pLocData = (const WORD*)((size_t)pLoc + sizeof(IMAGE_BASE_RELOCATION));
    // 计算本节需要修正的重定位项（地址）的数目。
    size_t nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
    for(size_t i = 0; i < nNumberOfReloc; ++i)
      {
      // 每个 WORD 由两部分组成。高 4 位指出了重定位的类型，WINNT.H 中的一系列 IMAGE_REL_BASED_xxx 定义了重定位类型的取值。
      // 低 12 位是相对于 VirtualAddress 域的偏移，指出了必须进行重定位的位置。
#ifdef _WIN64
      const WORD Flag = 0xA000;
      // 对于 IA-64 的可执行文件，重定位似乎总是 IMAGE_REL_BASED_DIR64 类型的。
#else
      const WORD Flag = 0x3000;
      // 对于 x86 的可执行文件，所有的基址重定位都是 IMAGE_REL_BASED_HIGHLOW 类型的。
#endif
      if(Flag != (pLocData[i] & 0xF000)) continue;
      // 需要修正。
      auto& Address = *(size_t*)((size_t)&DosHeader + pLoc->VirtualAddress + (pLocData[i] & 0xFFF));
      Address += Delta;
      }
    pLoc = (PIMAGE_BASE_RELOCATION)((size_t)pLoc + pLoc->SizeOfBlock);
    }
  return Success;
  }
static void* RelocationEnd()
  {
  return &Relocation;
  }
////////////////////////////////////////////////////////////////
struct ImportTableST
  {
  LPVOID PE;
  decltype(&LoadLibraryA) LoadLibraryA;
  decltype(&GetProcAddress) GetProcAddress;
  };
static DWORD WINAPI ImportTable(LPVOID lpParam)
  {
  const auto& st = *(const ImportTableST*)lpParam;

  const auto& DosHeader = *(const IMAGE_DOS_HEADER*)st.PE;
  const auto& NtHeaders = *(const IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);

  auto pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((size_t)&DosHeader + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

  for(; 0 != pImportTable->OriginalFirstThunk; ++pImportTable)
    {
    // 获取导入表中 DLL 名称并加载。
    auto pDllName = (const char*)((size_t)&DosHeader + pImportTable->Name);
    auto hDll = st.LoadLibraryA(pDllName);
    if(nullptr == hDll) return XImportDLL;

    // 获取 OriginalFirstThunk 以及对应的导入函数名称表首地址。
    auto lpImportNameArray = (PIMAGE_THUNK_DATA)((size_t)&DosHeader + pImportTable->OriginalFirstThunk);
    // 获取 FirstThunk 以及对应的导入函数地址表首地址。
    auto lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((size_t)&DosHeader + pImportTable->FirstThunk);
    for(size_t i = 0; 0 != lpImportNameArray[i].u1.AddressOfData; ++i)
      {
      // 获取IMAGE_IMPORT_BY_NAME结构
      auto lpImportByName = (PIMAGE_IMPORT_BY_NAME)((size_t)&DosHeader + lpImportNameArray[i].u1.AddressOfData);
      // 判断导出函数是序号导出还是函数名称导出。
      // 当 IMAGE_THUNK_DATA 值的最高位为 1 时，表示函数以序号方式输入，这时，低位被看做是一个函数序号。
      const auto Flag = (size_t)0x1 << (sizeof(size_t) * 8 - 1);
      auto FuncAddr = st.GetProcAddress(hDll,
        (Flag & lpImportNameArray[i].u1.Ordinal) ?
          (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF) :
          (LPCSTR)lpImportByName->Name);
      // 注意此处的函数地址表的赋值，要对照PE格式进行装载。
      lpImportFuncAddrArray[i].u1.Function = (size_t)FuncAddr;
      }
    }
  return Success;
  }
static void* ImportTableEnd()
  {
  return &ImportTable;
  }
////////////////////////////////////////////////////////////////
static DWORD WINAPI SetImageBase(LPVOID lpParam)
  {
  const auto& DosHeader = **(IMAGE_DOS_HEADER**)lpParam;
  const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
  const auto offset = (size_t)&(NtHeaders.OptionalHeader.ImageBase) - (size_t)&DosHeader;
  void** pImageBase = (void**)((size_t)&DosHeader + offset);
  void* ImageBase = (void*)&DosHeader;
  *pImageBase = ImageBase;
  return Success;
  }
static void* SetImageBaseEnd()
  {
  return &SetImageBase;
  }
////////////////////////////////////////////////////////////////
struct ExecuteTLSST
  {
  LPVOID PE;
  DWORD dwReason;
  };
static DWORD WINAPI ExecuteTLS(LPVOID lpParam)
  {
  const auto& st = *(const ExecuteTLSST*)lpParam;

  const auto& DosHeader = *(IMAGE_DOS_HEADER*)st.PE;
  const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
  auto& TLSDirectory = *(IMAGE_DATA_DIRECTORY*)&NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  if(0 == TLSDirectory.VirtualAddress)  return Success;
  auto& tls = *(IMAGE_TLS_DIRECTORY*)((size_t)&DosHeader + TLSDirectory.VirtualAddress);
  auto callback = (PIMAGE_TLS_CALLBACK*)tls.AddressOfCallBacks;
  if(0 == callback) return Success;
  for(; *callback; ++callback)
    {
    (*callback)((LPVOID)&DosHeader, st.dwReason, nullptr);
    }
  return Success;
  }
static void* ExecuteTLSEnd()
  {
  return &ExecuteTLS;
  }
////////////////////////////////////////////////////////////////
struct ExecuteDllMainST
  {
  LPVOID PE;
  DWORD dwReason;
  };
static DWORD WINAPI ExecuteDllMain(LPVOID lpParam)
  {
  const auto& st = *(const ExecuteDllMainST*)lpParam;

  const IMAGE_DOS_HEADER& DosHeader = *(IMAGE_DOS_HEADER*)st.PE;
  const IMAGE_NT_HEADERS& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
  using DllMainFunction = BOOL(WINAPI*)(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved);
  auto DllMain = (DllMainFunction)((size_t)&DosHeader + NtHeaders.OptionalHeader.AddressOfEntryPoint);
  DllMain((HINSTANCE)&DosHeader, st.dwReason, nullptr);
  return Success;
  }
static void* ExecuteDllMainEnd()
  {
  return &ExecuteDllMain;
  }
////////////////////////////////////////////////////////////////
struct UnloadImportST
  {
  LPVOID PE;
  decltype(&GetModuleHandleA) GetModuleHandleA;
  decltype(&FreeLibrary) FreeLibrary;
  };
static DWORD WINAPI UnloadImport(LPVOID lpParam)
  {
  const auto& st = *(const UnloadImportST*)lpParam;

  const auto& DosHeader = *(IMAGE_DOS_HEADER*)st.PE;
  const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
  PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((size_t)&DosHeader + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

  for(; 0 != pImportTable->OriginalFirstThunk; ++pImportTable)
    {
    LPCSTR pDllName = (LPCSTR)((size_t)&DosHeader + pImportTable->Name);
    HMODULE hLibModule = st.GetModuleHandleA(pDllName);
    if(NULL != hLibModule)
      {
      st.FreeLibrary(hLibModule);
      }
    }
  return Success;
  }
static void* UnloadImportEnd()
  {
  return &UnloadImport;
  }
////////////////////////////////////////////////////////////////
Result LoadDll(HANDLE hProcess, LPVOID PE)
  {
#define SCSET(func) &func, (size_t)&func##End - (size_t)&func
  // 重定位。注意：重定位之前不能填写加载基址。
  auto res = DoShellcode(hProcess, SCSET(Relocation), PE);
  if(!IsOK(res)) return res;
  // 填写导入表。
  const ImportTableST itst = {PE, &LoadLibraryA, &GetProcAddress};
  res = DoShellcode(hProcess, SCSET(ImportTable), itst);
  if(!IsOK(res)) return res;
  // 填写文件加载基址。
  res = DoShellcode(hProcess, SCSET(SetImageBase), PE);
  if(!IsOK(res)) return res;
  // TLS
  const ExecuteTLSST etst = {PE, DLL_PROCESS_ATTACH};
  res = DoShellcode(hProcess, SCSET(ExecuteTLS), etst);
  if(!IsOK(res)) return res;
  // 运行入口函数。
  const ExecuteDllMainST edst = {PE, DLL_PROCESS_ATTACH};
  res = DoShellcode(hProcess, SCSET(ExecuteDllMain), edst);
  if(!IsOK(res)) return res;
#undef SCSET
  return XRETURN(PE);
  }
////////////////////////////////////////////////////////////////
Result LoadDll(HANDLE hProcess, LPCTSTR lpFileName, Decode_Function Decode)
  {
  auto res = LoadFile(lpFileName, Decode);
  if(!IsOK(res))  return res;

  auto hMem = (HLOCAL)res;
  res = Mapping(hProcess, hMem);
  LocalFree(hMem);
  if(!IsOK(res)) return res;
  auto PE = (LPVOID)res;

  res = LoadDll(hProcess, PE);
  if(!IsOK(res))
    {
    VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
    }
  return res;
  }
Result LoadDll(LPCTSTR pid, LPCTSTR lpFileName, Decode_Function Decode)
  {
  auto res = OpenProcess(pid);
  if(!IsOK(res)) return res;
  auto hProcess = (HANDLE)res;

  res = LoadDll(hProcess, lpFileName, Decode);
  
  CloseHandle(hProcess);
  
  return res;
  }
////////////////////////////////////////////////////////////////
Result LoadDll(HANDLE           hProcess,
               HMODULE          hModule,
               LPCTSTR          lpName,
               LPCTSTR          lpType,
               Decode_Function  Decode)
  {
  auto res = LoadRes(hModule, lpName, lpType, Decode);
  if(!IsOK(res)) return res;
  
  auto hMem = (HLOCAL)res;
  res = Mapping(hProcess, hMem);
  LocalFree(hMem);
  if(!IsOK(res)) return res;
  auto PE = (LPVOID)res;

  res = LoadDll(hProcess, PE);
  if(!IsOK(res))
    {
    VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
    }

  return res;
  }
Result LoadDll(LPCTSTR          pid,
               HMODULE          hModule,
               LPCTSTR          lpName,
               LPCTSTR          lpType,
               Decode_Function  Decode)
  {
  auto res = OpenProcess(pid);
  if(!IsOK(res)) return res;
  auto hProcess = (HANDLE)res;
  
  res = LoadDll(hProcess, hModule, lpName, lpType, Decode);
  
  CloseHandle(hProcess);
  
  return res;
  }
////////////////////////////////////////////////////////////////
UnloadDllST UnloadDll(HANDLE hProcess, LPVOID PE, const bool release_pe)
  {
  UnloadDllST st;
  st.ex = XRETURN(Success);
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
  if(release_pe) VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
  return st;
  }
UnloadDllST UnloadDll(LPCTSTR pid, LPVOID PE)
  {
  UnloadDllST st;
  st.ex = OpenProcess(pid);
  if(!IsOK(st.ex)) return st;
  auto hProcess = (HANDLE)st.ex;

  st = UnloadDll(hProcess, PE, true);
  CloseHandle(hProcess);
  return st;
  }
////////////////////////////////////////////////////////////////
Result LocalDllProcAddr(LPVOID PE, LPCSTR lpProcName, const bool fuzzy)
  {
  try
    {
    const auto& DosHeader = *(const IMAGE_DOS_HEADER*)PE;
    const auto& NtHeaders = *(const IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    const auto& ExportEntry = *(const IMAGE_DATA_DIRECTORY*)&NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if(0 == ExportEntry.Size) return XERROR(XNoExport);
    
    const auto& ExportTable = *(const IMAGE_EXPORT_DIRECTORY*)((size_t)&DosHeader + ExportEntry.VirtualAddress);
    auto pAddressOfFunction = (const DWORD*)((size_t)&DosHeader + ExportTable.AddressOfFunctions);
    
    LPVOID addr = NULL;

    const auto Name = (DWORD)(size_t)lpProcName;
    if(0 == (Name & 0xFFFF0000))
      {
      // 序号查找。
      const auto dwBase = ExportTable.Base;
      if(Name < dwBase) return XERROR(XIndex);
      if(Name > dwBase + ExportTable.NumberOfFunctions - 1) return XERROR(XIndex);
      addr = (LPVOID)((size_t)&DosHeader + pAddressOfFunction[Name - dwBase]);
      }
    else
      {
      auto pAddressOfName = (const DWORD*)((size_t)&DosHeader + ExportTable.AddressOfNames);
      auto pAddressOfNameOrdinals = (const WORD*)((size_t)&DosHeader + ExportTable.AddressOfNameOrdinals);
      for(size_t i = 0; i < (size_t)ExportTable.NumberOfNames; ++i)
        {
        auto name = (LPCSTR)((size_t)&DosHeader + pAddressOfName[i]);
        if(fuzzy)
          {
          if(nullptr != strstr(name, lpProcName))
            {
            addr = (LPVOID)((size_t)&DosHeader + pAddressOfFunction[pAddressOfNameOrdinals[i]]);
            break;
            }
          }
        else
          {
          if(0 == strcmp(name, lpProcName))
            {
            addr = (LPVOID)((size_t)&DosHeader + pAddressOfFunction[pAddressOfNameOrdinals[i]]);
            break;
            }
          }
        }
      }
    
    if(NULL == addr) return XERROR(XNoFind);

    // 判断是否合法。
    if((size_t)addr < (size_t)ExportEntry.VirtualAddress) return XRETURN(addr);
    if((size_t)addr > ((size_t)ExportEntry.VirtualAddress + ExportEntry.Size)) return XRETURN(addr);

    CHAR reload[MAX_PATH] = {'\0'};
    lstrcpyA(reload, (LPCSTR)addr);

    LPSTR p = strchr(reload, '.');
    if(NULL == p) return XERROR(XNoMod);
    *p = '\0';
    ++p;
    HMODULE hMod = GetModuleHandleA(reload);
    if(NULL == hMod)  return XERROR(XGetModuleHandleA);
    FARPROC func = GetProcAddress(hMod, p);
    if(NULL == func)  return XERROR(XGetProcAddress);
    return XRETURN(func);
    }
  catch(...)
    {
    return XERROR(XLocalDllProcAddr);
    }
  }
////////////////////////////////////////////////////////////////
struct RemoteDllProcAddrST
  {
  LPVOID PE;
  bool fuzzy;
  decltype(&GetModuleHandleA) GetModuleHandleA;
  decltype(&GetProcAddress) GetProcAddress;
  LPCSTR lpProcName;
  CHAR ProcName[MAX_PATH];
  };
static DWORD WINAPI RemoteDllProcAddrShellCode(LPVOID lpParam)
  {
  const auto& st = *(const RemoteDllProcAddrST*)lpParam;

  const auto stsize = (sizeof(st) + 0x10) - (sizeof(st) % 0x10);
  auto& res = *(Result*)((size_t)lpParam + stsize);

  const auto& DosHeader = *(const IMAGE_DOS_HEADER*)st.PE;
  const auto& NtHeaders = *(const IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
  const auto& ExportEntry = *(const IMAGE_DATA_DIRECTORY*)&NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  
  if(0 == ExportEntry.Size) return XNoExport;
  
  const auto& ExportTable = *(const IMAGE_EXPORT_DIRECTORY*)((size_t)&DosHeader + ExportEntry.VirtualAddress);
  auto pAddressOfFunction = (const DWORD*)((size_t)&DosHeader + ExportTable.AddressOfFunctions);
  
  LPVOID addr = NULL;

  const auto Name = (DWORD)(size_t)st.lpProcName;
  if(0 == (Name & 0xFFFF0000))
    {
    // 序号查找。
    const auto dwBase = ExportTable.Base;
    if(Name < dwBase) return XIndex;
    if(Name > dwBase + ExportTable.NumberOfFunctions - 1) return XIndex;
    addr = (LPVOID)((size_t)&DosHeader + pAddressOfFunction[Name - dwBase]);
    }
  else
    {
    auto pAddressOfName = (const DWORD*)((size_t)&DosHeader + ExportTable.AddressOfNames);
    auto pAddressOfNameOrdinals = (const WORD*)((size_t)&DosHeader + ExportTable.AddressOfNameOrdinals);
    for(size_t i = 0; i < (size_t)ExportTable.NumberOfNames; ++i)
      {
      auto name = (LPCSTR)((size_t)&DosHeader + pAddressOfName[i]);
      if(st.fuzzy)
        {
        bool ok = false;
        for(size_t x = 0; '\0' != name[x]; ++x)
          {
          if('\0' == st.ProcName[0]) break;
          for(size_t k = 0; name[x + k] == st.ProcName[k]; ++k)
            {
            if('\0' == st.ProcName[k + 1])
              {
              ok = true;
              break;
              }
            }
          if(ok) break;
          }
        if(ok)
          {
          addr = (LPVOID)((size_t)&DosHeader + pAddressOfFunction[pAddressOfNameOrdinals[i]]);
          break;
          }
        }
      else
        {
        bool ok = false;
        for(size_t x = 0; !ok; ++x)
          {
          if(name[x] != st.ProcName[x]) break;
          if('\0' == name[x])
            {
            ok = true;
            break;
            }
          }
        if(ok)
          {
          addr = (LPVOID)((size_t)&DosHeader + pAddressOfFunction[pAddressOfNameOrdinals[i]]);
          break;
          }
        }
      }
    }
  
  if(NULL == addr) return XNoFind;

  // 判断是否合法。
  if((size_t)addr < (size_t)ExportEntry.VirtualAddress)
    {
    res = (Result)addr;
    return Success;
    }
  if((size_t)addr > ((size_t)ExportEntry.VirtualAddress + ExportEntry.Size))
    {
    res = (Result)addr;
    return Success;
    }

  CHAR reload[MAX_PATH] = {'\0'};
  for(size_t i = 0; '\0' != *(CHAR*)((size_t)addr + i); ++i)
    {
    reload[i] = *(CHAR*)((size_t)addr + i);
    }

  LPSTR p = nullptr;
  for(size_t i = 0; '\0' != reload[i]; ++i)
    {
    if('.' == reload[i])
      {
      p = &reload[i];
      break;
      }
    }
  if(nullptr == p) return XNoMod;
  *p = '\0';
  ++p;
  HMODULE hMod = st.GetModuleHandleA(reload);
  if(NULL == hMod)  return XGetModuleHandleA;
  FARPROC func = st.GetProcAddress(hMod, p);
  if(NULL == func)  return XGetProcAddress;
  res = (Result)func;
  return Success;
  }
static void* RemoteDllProcAddrShellCodeEnd()
  {
  return &RemoteDllProcAddrShellCode;
  }
Result RemoteDllProcAddr(HANDLE hProcess, LPVOID PE, LPCSTR lpProcName, const bool fuzzy)
  {
  RemoteDllProcAddrST st;
  st.PE = PE;
  st.fuzzy = fuzzy;
  st.GetModuleHandleA = &GetModuleHandleA;
  st.GetProcAddress = &GetProcAddress;
  st.lpProcName = lpProcName;
  const auto Name = (DWORD)(size_t)st.lpProcName;
  if(0 != (Name & 0xFFFF0000))
    {
    lstrcpyA(&st.ProcName[0], lpProcName);
    }

#define SCSET(func) &func, (size_t)&func##End - (size_t)&func
  return DoShellcode(hProcess, SCSET(RemoteDllProcAddrShellCode), st, true);
#undef SCSET
  }
////////////////////////////////////////////////////////////////
  }