#include "xit.h"

#include <Tlhelp32.h>

#include <string>

namespace xit
  {
////////////////////////////////////////////////////////////////
ERROR_ENUM Error(const Result res)
  {
  return (ERROR_ENUM)((res >> 32) & 0x7FFFFFFF);
  }

DWORD ErrorEx(const Result res)
  {
  return (DWORD)(res & 0xFFFFFFFF);
  }

static Result XERROR(const ERROR_ENUM ec, const DWORD le = GetLastError())
  {
  Result res = ec | 0x80000000;
  res <<= 32;
  return res | le;
  }

template<typename T> Result XRETURN(const T v)
  {
  return (Result)v;
  }

bool IsOK(const Result res)
  {
  return 0 == (res & 0x8000000000000000);
  }
////////////////////////////////////////////////////////////////
Result UpperToken(HANDLE hProcess)
  {
  HANDLE TokenHandle = nullptr;
  if(FALSE == OpenProcessToken(hProcess,
                               TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                               &TokenHandle))
    {
    return XERROR(XOpenProcessToken);
    }
  TOKEN_PRIVILEGES NewState;
  NewState.PrivilegeCount = 1;
  if(FALSE == LookupPrivilegeValue(nullptr,
                                   SE_DEBUG_NAME,
                                   &(NewState.Privileges[0].Luid)))
    {
    const Result r = XERROR(XLookupPrivilegeValue);
    CloseHandle(TokenHandle);
    return r;
    }
  NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  if(FALSE == AdjustTokenPrivileges(TokenHandle,
                                    FALSE,
                                    &NewState,
                                    sizeof(NewState),
                                    nullptr,
                                    nullptr))
    {
    const Result r = XERROR(XAdjustTokenPrivileges);
    CloseHandle(TokenHandle);
    return r;
    }
  CloseHandle(TokenHandle);
  return XRETURN(Success);
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
  if(0 != PID) return XRETURN(PID);

  auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if(INVALID_HANDLE_VALUE == hSnapshot)
    return XERROR(XCreateToolhelp32Snapshot);
  
  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(pe);
  if(FALSE == Process32First(hSnapshot, &pe))
    {
    const auto r = XERROR(XProcess32First);
    CloseHandle(hSnapshot);
    return r;
    }

  do
    {
#ifdef UNICODE
    if(0 == _wcsicmp(pid, pe.szExeFile))
#else
    if(0 == _stricmp(pid, pe.szExeFile))
#endif
      {
      CloseHandle(hSnapshot);
      return XRETURN(pe.th32ProcessID);
      }
    }while(FALSE != Process32Next(hSnapshot, &pe));

  CloseHandle(hSnapshot);
  return XERROR(XGetPID);
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
    if(ULLONG_MAX != MOD) return XERROR(XGetModule, 1);
#else
    unsigned long MOD =
  #ifdef UNICODE
    wcstoul(hmod, &str_end, 16);
  #else
    strtoul(hmod, &str_end, 16);
  #endif
    if(ULONG_MAX != MOD) return XERROR(XGetModule, 1);
#endif
    // 完全转换完成，并转换成功才行。
    if(TEXT('\0') != *str_end) return XERROR(XGetModule, 2);
    if(0 == MOD) return XERROR(XGetModule, 3);
    if(MOD < 0x10000) MOD <<= 16;
    return XRETURN(MOD);
    }
  catch(...)
    {
    return XERROR(XGetModule);
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
  auto hFile = CreateFileW(
    lpFileName,
    GENERIC_READ,
    FILE_SHARE_READ,
    nullptr,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_READONLY,
    nullptr);
  if(INVALID_HANDLE_VALUE == hFile)
    {
    return XERROR(XCreateFile);
    }
  // 查询大小。
  LARGE_INTEGER FileSize;
  if(FALSE == GetFileSizeEx(hFile, &FileSize))
    {
    const auto r = XERROR(XGetFileSizeEx);
    CloseHandle(hFile);
    return r;
    }
  if(0 != FileSize.HighPart)
    {
    const auto r = XERROR(XLarge);
    CloseHandle(hFile);
    return r;
    }
  // 申请内存。
  const auto uBytes = FileSize.LowPart;
  auto hMem = LocalAlloc(LMEM_MOVEABLE | LMEM_ZEROINIT, uBytes);
  if(nullptr == hMem)
    {
    const auto r = XERROR(XLocalAlloc);
    CloseHandle(hFile);
    return r;
    }
  // 锁定内存。
  auto lpBuffer = LocalLock(hMem);
  if(nullptr == lpBuffer)
    {
    const auto r = XERROR(XLocalLock);
    CloseHandle(hFile);
    LocalFree(hMem);
    return r;
    }
  // 读取文件。
  DWORD NumberOfBytesRead = 0;
  if(FALSE == ReadFile(hFile, lpBuffer, uBytes, &NumberOfBytesRead, nullptr))
    {
    const auto r = XERROR(XReadFile);
    CloseHandle(hFile);
    LocalUnlock(lpBuffer);
    LocalFree(hMem);
    return r;
    }
  // 释放文件句柄。
  CloseHandle(hFile);

  // 申请可写缓存。
  auto hMEM = LocalAlloc(LMEM_MOVEABLE | LMEM_ZEROINIT, uBytes);
  if(nullptr == hMEM)
    {
    const auto r = XERROR(XLocalAlloc);
    LocalUnlock(lpBuffer);
    LocalFree(hMem);
    return r;
    }
  // 锁定内存。
  auto BIN = LocalLock(hMEM);
  if(nullptr == BIN)
    {
    const auto r = XERROR(XLocalLock);
    LocalUnlock(lpBuffer);
    LocalFree(hMem);
    LocalFree(hMEM);
    return r;
    }
  
  const auto ok = Decode(BIN, lpBuffer, uBytes);
  
  LocalUnlock(lpBuffer);
  LocalFree(hMem);
  LocalUnlock(BIN);

  if(!ok)
    {
    LocalFree(hMEM);
    return XERROR(XDecode);
    }
  return XRETURN(hMEM);
  }
////////////////////////////////////////////////////////////////
Result LoadRes(HMODULE hModule, LPCTSTR lpName, LPCTSTR lpType, Decode_Function Decode)
  {
  // 加载资源。注意到：资源句柄无需释放。
  auto hResInfo = FindResource(hModule, lpName, lpType);
  if(nullptr == hResInfo) return XERROR(XFindResource);
  auto hResData = LoadResource(hModule, hResInfo);
  if(nullptr == hResData) return XERROR(XLoadResource);
  auto RES = LockResource(hResData);
  if(nullptr == RES) return XERROR(XLockResource);
  auto uBytes = SizeofResource(hModule, hResInfo);
  if(0 == uBytes) return XERROR(XSizeofResource);
  // 申请可写缓存。
  auto hMem = LocalAlloc(LMEM_MOVEABLE | LMEM_ZEROINIT, uBytes);
  if(nullptr == hMem) return XERROR(XLocalAlloc);
  auto BIN = LocalLock(hMem);
  if(nullptr == BIN)
    {
    const auto r = XERROR(XLocalLock);
    LocalFree(hMem);
    return r;
    }
  const auto ok = Decode(BIN, RES, uBytes);
  
  LocalUnlock(BIN);

  if(!ok)
    {
    LocalFree(hMem);
    return XERROR(XDecode);
    }
  return XRETURN(hMem);
  }
////////////////////////////////////////////////////////////////
Result Mapping(HANDLE hProcess, HLOCAL hMem)
  {
  try
    {
    auto BIN = LocalLock(hMem);
    if(nullptr == BIN)
      {
      return XERROR(XMappingLock);
      }
    const auto& DosHeader = *(IMAGE_DOS_HEADER*)BIN;
    const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    // 获取镜像大小。
    const auto SizeOfImage = NtHeaders.OptionalHeader.SizeOfImage;
    auto PE = VirtualAllocEx(hProcess, nullptr, SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(nullptr == PE)
      {
      const auto r = XERROR(XVirtualAllocEx);
      LocalUnlock(BIN);
      return r;
      }
    // 所有 头 + 节表 头大小。
    const SIZE_T SizeOfHeaders = NtHeaders.OptionalHeader.SizeOfHeaders;
    // 写入所有 头 + 节表 头。
    if(FALSE == WriteProcessMemory(hProcess, PE, &DosHeader, SizeOfHeaders, nullptr))
      {
      const auto r = XERROR(XMappingHeader);
      LocalUnlock(BIN);
      VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
      return r;
      }
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
      auto dst = (void*)((size_t)PE + pSectionHeader->VirtualAddress);
      if(FALSE == WriteProcessMemory(hProcess, dst, src, pSectionHeader->SizeOfRawData, nullptr))
        {
        const auto r = XERROR(XMappingSection);
        LocalUnlock(BIN);
        VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
        return r;
        }
      ++pSectionHeader;
      }
    return XRETURN(PE);
    }
  catch(...)
    {
    return XERROR(XMapping);
    }
  }
////////////////////////////////////////////////////////////////
Result OpenProcess(const DWORD PID)
  {
  auto hProcess = ::OpenProcess(
    PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
    TRUE, PID);
  if(nullptr == hProcess) return XERROR(XOpenProcess);
  return XRETURN(hProcess);
  }
Result OpenProcess(LPCTSTR pid)
  {
  auto res = GetPID(pid);
  if(!IsOK(res)) return res;
  const auto PID = (const DWORD)res;
  return OpenProcess(PID);
  }
////////////////////////////////////////////////////////////////
template<class T>
static Result DoShellcode(HANDLE hProcess, LPTHREAD_START_ROUTINE shellcode, const size_t size, const T& st, const bool expand = false)
  {
  const auto alignsize = (size + 0x10) - (size % 0x10);
  const auto stsize = (sizeof(st) + 0x10) - (sizeof(st) % 0x10);
  const auto expandsize = expand ? sizeof(Result) : 0;
  const size_t Size = alignsize + stsize + expandsize;

  auto Shellcode = VirtualAllocEx(hProcess, nullptr, Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if(nullptr == Shellcode)
    {
    return XERROR(XDoShellcodeNew);
    }
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
    const auto res = XRETURN(Success);
    if(FALSE == WriteProcessMemory(hProcess, pex, &res, sizeof(res), nullptr))
      {
      const auto r = XERROR(XWriteProcessMemory);
      VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
      return r;
      }
    }
  auto hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)Shellcode, pst, 0, nullptr);
  if(nullptr == hThread)
    {
    const auto r = XERROR(XCreateRemoteThread);
    VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
    return r;
    }
  const auto wait = WaitForSingleObject(hThread, INFINITE);
  if(WAIT_TIMEOUT == wait)
    {
    const auto r = XERROR(XWaitForSingleObject_timeout);
    TerminateThread(hThread, 0);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
    return r;
    }
  if(WAIT_FAILED == wait ||  WAIT_OBJECT_0 != wait)
    {
    const auto r = XERROR(XWaitForSingleObject_fail);
    TerminateThread(hThread, 0);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
    return r;
    }
  DWORD ec;
  if(FALSE == GetExitCodeThread(hThread, &ec))
    {
    const auto r = XERROR(XGetExitCodeThread);
    TerminateThread(hThread, 0);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
    return r;
    }
  if(Success != ec)
    {
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
    return XERROR(XDoShellcode, ec);
    }
  if(expand)
    {
    auto pex = (LPVOID)((size_t)Shellcode + alignsize + stsize);
    Result res;
    if(FALSE == ReadProcessMemory(hProcess, pex, &res, sizeof(res), nullptr))
      {
      CloseHandle(hThread);
      VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
      return XERROR(XReadProcessMemory);
      }
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, Shellcode, 0, MEM_RELEASE);
    return res;
    }
  CloseHandle(hThread);
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
  // 重定位。注意：重定位之前不能填写加载基址。
  auto res = DoShellcode(hProcess,
    &Relocation, (size_t)&RelocationEnd - (size_t)&Relocation, PE);
  if(!IsOK(res)) return res;
  // 填写导入表。
  const ImportTableST itst = {PE, &LoadLibraryA, &GetProcAddress};
  res = DoShellcode(hProcess,
    &ImportTable, (size_t)&ImportTableEnd - (size_t)ImportTable, itst);
  if(!IsOK(res)) return res;
  // 填写文件加载基址。
  res = DoShellcode(hProcess,
    &SetImageBase, (size_t)&SetImageBaseEnd - (size_t)&SetImageBase, PE);
  if(!IsOK(res)) return res;
  // TLS
  const ExecuteTLSST etst = {PE, DLL_PROCESS_ATTACH};
  res = DoShellcode(hProcess,
    &ExecuteTLS, (size_t)&ExecuteTLSEnd - (size_t)&ExecuteTLS, etst);
  if(!IsOK(res)) return res;
  // 运行入口函数。
  const ExecuteDllMainST edst = {PE, DLL_PROCESS_ATTACH};
  res = DoShellcode(hProcess,
    &ExecuteDllMain, (size_t)&ExecuteDllMainEnd - (size_t)&ExecuteDllMain, edst);
  if(!IsOK(res)) return res;
  return XRETURN(PE);
  }
Result LoadDll(LPCTSTR pid, LPCTSTR lpFileName, Decode_Function Decode)
  {
  // 打开进程。
  auto res = OpenProcess(pid);
  if(!IsOK(res)) return res;
  auto hProcess = (HANDLE)res;
  // 加载文件。
  res = LoadFile(lpFileName, Decode);
  if(!IsOK(res))
    {
    CloseHandle(hProcess);
    return res;
    }

  auto hMem = (HLOCAL)res;
  res = Mapping(hProcess, hMem);
  LocalFree(hMem);

  if(!IsOK(res))
    {
    CloseHandle(hProcess);
    return res;
    }

  auto PE = (LPVOID)res;

  res = LoadDll(hProcess, PE);

  if(!IsOK(res))
    {
    VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
    }
  CloseHandle(hProcess);

  return res;
  }
Result LoadDll(LPCTSTR          pid,
               HMODULE          hModule,
               LPCTSTR          lpName,
               LPCTSTR          lpType,
               Decode_Function  Decode)
  {
  // 打开进程。
  auto res = OpenProcess(pid);
  if(!IsOK(res)) return res;
  auto hProcess = (HANDLE)res;
  // 加载资源。
  res = LoadRes(hModule, lpName, lpType, Decode);
  if(!IsOK(res))
    {
    CloseHandle(hProcess);
    return res;
    }
  
  auto hMem = (HLOCAL)res;
  res = Mapping(hProcess, hMem);
  LocalFree(hMem);

  if(!IsOK(res))
    {
    CloseHandle(hProcess);
    return res;
    }

  auto PE = (LPVOID)res;

  res = LoadDll(hProcess, PE);

  if(!IsOK(res))
    {
    VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
    }
  CloseHandle(hProcess);

  return res;
  }
////////////////////////////////////////////////////////////////
UnloadDllST UnloadDll(HANDLE hProcess, LPVOID PE)
  {
  UnloadDllST st;
  st.ex = XRETURN(Success);
  // TLS
  const ExecuteTLSST etst = {PE, DLL_PROCESS_DETACH};
  st.tls = DoShellcode(hProcess,
    &ExecuteTLS, ((size_t)&ExecuteTLSEnd - (size_t)&ExecuteTLS), etst);
  // 运行入口函数。
  const ExecuteDllMainST edst = {PE, DLL_PROCESS_DETACH};
  st.main = DoShellcode(hProcess,
    &ExecuteDllMain, (size_t)&ExecuteDllMainEnd - (size_t)&ExecuteDllMain, edst);
  // 卸载导入 DLL 。
  const UnloadImportST uist = {PE, &GetModuleHandleA, &FreeLibrary};
  st.import = DoShellcode(hProcess,
    &UnloadImport, (size_t)&UnloadImportEnd - (size_t)&UnloadImport, uist);
  return st;
  }
UnloadDllST UnloadDll(LPCTSTR pid, LPVOID PE)
  {
  // 打开进程。
  UnloadDllST st;
  st.ex = OpenProcess(pid);
  if(!IsOK(st.ex)) return st;
  auto hProcess = (HANDLE)st.ex;

  st = UnloadDll(hProcess, PE);
  VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
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
  return DoShellcode(hProcess, &RemoteDllProcAddrShellCode,
    (size_t)&RemoteDllProcAddrShellCodeEnd - (size_t)&RemoteDllProcAddrShellCode, st, true);
  }
////////////////////////////////////////////////////////////////
  }