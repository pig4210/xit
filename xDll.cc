#include "xDll.h"

#include "xalloc.h"

////////////////////////////////////////////////////////////////
static bool MappingDll(std::shared_ptr<xalloc>& PE, const IMAGE_DOS_HEADER& DosHeader)
  {
  try
    {
    xlog() << __FUNCTION__ "...\r\n    ";

    auto& Process = PE->Process;

    const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    // 所有 头 + 节表 头大小。
    const auto SizeOfHeaders = NtHeaders.OptionalHeader.SizeOfHeaders;
    xshow(SizeOfHeaders, "Write Headers", "        ");
    // 加载所有 头 + 节表 头。
    if(FALSE == WriteProcessMemory(Process->hHandle, PE->Memory, &DosHeader, SizeOfHeaders, nullptr))
      {
      xshowerr("Fail");
      return false;
      }
    xlog() << "Done.\r\n    ";
    // 节表数量。
    const auto NumberOfSections = NtHeaders.FileHeader.NumberOfSections;
    xshow(NumberOfSections, "Sections Number", "        ");
    // 获取第一个 节表头 的地址。
    auto pSectionHeader = (IMAGE_SECTION_HEADER*)((size_t)&NtHeaders + sizeof(NtHeaders));
    for(size_t i = 0; i < NumberOfSections; ++i)
      {
      xlog() << "    " << i << ". ";
      xshow(pSectionHeader->SizeOfRawData, nullptr,
        ((i + 1) == NumberOfSections) ? "    " : "        ");
      if((0 == pSectionHeader->VirtualAddress) || (0 == pSectionHeader->SizeOfRawData))
        {
        ++pSectionHeader;
        continue;
        }
      auto src = (void*)((size_t)&DosHeader + pSectionHeader->PointerToRawData);
      auto dst = (void*)((size_t)PE->Memory + pSectionHeader->VirtualAddress);
      if(FALSE == WriteProcessMemory(Process->hHandle, dst, src, pSectionHeader->SizeOfRawData, nullptr))
        {
        xshowerr("Fail");
        return false;
        }
      ++pSectionHeader;
      }
    
    xlog() << "Done.\r\n";
    return true;
    }
  catch(...)
    {
    xlog() << "\r\n" xfunexpt "\r\n";
    return false;
    }
  }

////////////////////////////////////////////////////////////////
static std::shared_ptr<xalloc> CreateShellcode(std::shared_ptr<xhandle>& Process, const void* shellcode, const size_t size)
  {
  try
    {
    xlog() << "VirtualAllocEx...\r\n        ";
    auto Shellcode = std::make_shared<xalloc>(Process,
      VirtualAllocEx(Process->hHandle, nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if(!(*Shellcode))
      {
      xshowerr("Fail");
      return std::shared_ptr<xalloc>();
      }
    xshow(Shellcode->Memory, "Done.", "    ");
    xshow(size, "Write Shellcode...", "        ");
    if(FALSE == WriteProcessMemory(Process->hHandle, Shellcode->Memory, shellcode, size, nullptr))
      {
      xshowerr("Fail");
      return std::shared_ptr<xalloc>();
      }
    xlog() << "Done.\r\n    ";
    return Shellcode;
    }
  catch(...)
    {
    xlog() << "\r\n" xfunexpt "\r\n";
    return std::shared_ptr<xalloc>();
    }
  }

////////////////////////////////////////////////////////////////
static bool DoShellcode(std::shared_ptr<xhandle>& Process, LPTHREAD_START_ROUTINE Shellcode, LPVOID lpParam)
  {
  try
    {
    xlog() << "Create Thead...\r\n        ";
    auto Thread = std::make_shared<xhandle>(CreateRemoteThread(Process->hHandle, nullptr, 0, Shellcode, lpParam, 0, nullptr));
    if(!(*Thread))
      {
      xshowerr("Fail");
      return false;
      }
    xshow(Thread->hHandle, "Done", "    ");
    xlog() << "WaitForSingleObject...\r\n        ";
    const auto waitret = WaitForSingleObject(Thread->hHandle, INFINITE);
    if(waitret == WAIT_TIMEOUT)
      {
      xshowerr("Timeout");
      return false;
      }
    if(waitret == WAIT_FAILED || waitret != WAIT_OBJECT_0)
      {
      xshowerr("Fail");
      return false;
      }
    xlog() << "Done.\r\n    ";
    xlog() << "GetExitCodeThread...\r\n        ";
    DWORD ec;
    if(!GetExitCodeThread(Thread->hHandle, &ec))
      {
      xshowerr("Fail");
      return false;
      }
    if(ec == TRUE)
      {
      xlog() << "Done.\r\n";
      return true;
      }
    xlog() << "Done but return false.\r\n";
    return ec == TRUE;
    }
  catch(...)
    {
    xlog() << "\r\n" xfunexpt "\r\n";
    return false;
    }
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
static BOOL WINAPI DoRelocationShellcode(LPVOID Base)
  {
  const auto& DosHeader = *(IMAGE_DOS_HEADER*)Base;
  const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
  auto pLoc = (PIMAGE_BASE_RELOCATION)((size_t)&DosHeader + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

  // 是否有重定位表。
  if((void*)pLoc == (void*)&DosHeader)
    {
    return TRUE;
    }
  
  // 计算修正值。
  const auto Delta = (size_t)&DosHeader - NtHeaders.OptionalHeader.ImageBase;
  
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
  return TRUE;
  }
static auto DoRelocationShellcodeEnd()
  {
  return &DoRelocationShellcode;
  }
static bool DoRelocation(std::shared_ptr<xalloc>& PE)
  {
  try
    {
    auto& Process = PE->Process;
    xlog() << __FUNCTION__ "...\r\n    ";

    const auto ShellcodeSize = (size_t)&DoRelocationShellcodeEnd - (size_t)&DoRelocationShellcode;
    auto Shellcode = CreateShellcode(Process, &DoRelocationShellcode, ShellcodeSize);
    if(!(*Shellcode)) return false;

    return DoShellcode(Process, (LPTHREAD_START_ROUTINE)Shellcode->Memory, PE->Memory);
    }
  catch(...)
    {
    xlog() << "\r\n" xfunexpt "\r\n";
    return false;
    }
  }

////////////////////////////////////////////////////////////////
struct DoImportTableST
  {
  void* Base;
  decltype(&LoadLibraryA) LoadLibraryA;
  decltype(&GetProcAddress) GetProcAddress;
  };
static BOOL WINAPI DoImportTableShellcode(LPVOID lpParam)
  {
  const auto& st = *(const DoImportTableST*)lpParam;

  auto& DosHeader = *(IMAGE_DOS_HEADER*)st.Base;
  auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);

  auto pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((size_t)&DosHeader + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

  for(; 0 != pImportTable->OriginalFirstThunk; ++pImportTable)
    {
    // 获取导入表中 DLL 名称并加载。
    auto pDllName = (const char*)((size_t)&DosHeader + pImportTable->Name);
    auto hDll = st.LoadLibraryA(pDllName);
    if(nullptr == hDll) return FALSE;

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
      auto FuncAddr = st.GetProcAddress(hDll, (Flag & lpImportNameArray[i].u1.Ordinal) ?
        (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF) :
        (LPCSTR)lpImportByName->Name);
      // 注意此处的函数地址表的赋值，要对照PE格式进行装载。
      lpImportFuncAddrArray[i].u1.Function = (size_t)FuncAddr;
      }
    }
  return TRUE;
  }
static auto DoImportTableShellcodeEnd()
  {
  return &DoImportTableShellcode;
  }
static bool DoImportTable(std::shared_ptr<xalloc>& PE)
  {
  try
    {
    auto& Process = PE->Process;
    xlog() << __FUNCTION__ "...\r\n    ";

    const auto ShellcodeSize = (size_t)&DoImportTableShellcodeEnd - (size_t)&DoImportTableShellcode;
    const auto alignsize = (ShellcodeSize + 0x10) - (ShellcodeSize % 0x10);
    DoImportTableST st{PE->Memory, &LoadLibraryA, &GetProcAddress};
    std::string sc;
    sc.append((const char*)&DoImportTableShellcode, alignsize);
    sc.append((const char*)&st, sizeof(st));

    auto Shellcode = CreateShellcode(Process, sc.c_str(), sc.size());
    if(!(*Shellcode)) return false;

    return DoShellcode(Process, (LPTHREAD_START_ROUTINE)Shellcode->Memory, (void*)((size_t)Shellcode->Memory + alignsize));
    }
  catch(...)
    {
    xlog() << "\r\n" xfunexpt "\r\n";
    return false;
    }
  }

////////////////////////////////////////////////////////////////
static BOOL WINAPI DoExecuteTLSShellcode(LPVOID BASE)
  {
  const auto& DosHeader = *(IMAGE_DOS_HEADER*)BASE;
  const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
  auto& TLSDirectory = *(IMAGE_DATA_DIRECTORY*)&NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  if(0 == TLSDirectory.VirtualAddress)  return TRUE;
  auto& tls = *(IMAGE_TLS_DIRECTORY*)((size_t)&DosHeader + TLSDirectory.VirtualAddress);
  auto callback = (PIMAGE_TLS_CALLBACK*)tls.AddressOfCallBacks;
  if(0 == callback) return TRUE;
  for(; *callback; ++callback)
    {
    (*callback)((LPVOID)&DosHeader, DLL_PROCESS_ATTACH, NULL);
    }
  return TRUE;
  }
static auto DoExecuteTLSShellcodeEnd()
  {
  return &DoExecuteTLSShellcode;
  }
static bool DoExecuteTLS(std::shared_ptr<xalloc>& PE)
  {
  try
    {
    auto& Process = PE->Process;
    xlog() << __FUNCTION__ "...\r\n    ";

    const auto ShellcodeSize = (size_t)&DoExecuteTLSShellcodeEnd - (size_t)&DoExecuteTLSShellcode;
    auto Shellcode = CreateShellcode(Process, &DoExecuteTLSShellcode, ShellcodeSize);
    if(!(*Shellcode)) return false;

    return DoShellcode(Process, (LPTHREAD_START_ROUTINE)Shellcode->Memory, PE->Memory);
    }
  catch(...)
    {
    xlog() << "\r\n" xfunexpt "\r\n";
    return false;
    }
  }

////////////////////////////////////////////////////////////////
static BOOL WINAPI DoDllMainShellcode(LPVOID hInstance)
  {
  const auto& DosHeader = *(IMAGE_DOS_HEADER*)hInstance;
  const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
  using DllMainFunction = BOOL(WINAPI*)(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved);
  auto DllMain = (DllMainFunction)((size_t)&DosHeader + NtHeaders.OptionalHeader.AddressOfEntryPoint);
  return DllMain((HINSTANCE)hInstance, DLL_PROCESS_ATTACH, nullptr);
  }
static auto DoDllMainShellcodeEnd()
  {
  return &DoDllMainShellcode;
  }
static bool DoDllMain(std::shared_ptr<xalloc>& PE)
  {
  try
    {
    auto& Process = PE->Process;
    xlog() << __FUNCTION__ "...\r\n    ";

    const auto ShellcodeSize = (size_t)&DoDllMainShellcodeEnd - (size_t)&DoDllMainShellcode;
    auto Shellcode = CreateShellcode(Process, &DoDllMainShellcode, ShellcodeSize);
    if(!(*Shellcode)) return false;

    return DoShellcode(Process, (LPTHREAD_START_ROUTINE)Shellcode->Memory, PE->Memory);
    }
  catch(...)
    {
    xlog() << "\r\n" xfunexpt "\r\n";
    return false;
    }
  }

////////////////////////////////////////////////////////////////
bool LoadLibraryW(DWORD PID, const std::string& dllfile)
  {
  try
    {
    // 打开进程。
    xlog() << "OpenProcess...\r\n    ";
    auto Process = std::make_shared<xhandle>(OpenProcess(
    PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE, TRUE, PID));
    if(!(*Process))
      {
      xshowerr("Fail");
      return false;
      }
    xshow(Process->hHandle, "Done.");

    // 开辟空间。
    const auto& DosHeader = *(IMAGE_DOS_HEADER*)dllfile.c_str();
    const auto& NtHeaders = *(IMAGE_NT_HEADERS*)((size_t)&DosHeader + DosHeader.e_lfanew);
    // 获取镜像大小。
    const auto SizeOfImage = NtHeaders.OptionalHeader.SizeOfImage;
    xlog() << "VirtualAllocEx...\r\n    ";
    auto PE = std::make_shared<xalloc>(Process,
    VirtualAllocEx(Process->hHandle, nullptr, SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if(!(*PE))
      {
      xshowerr("Fail");
      return false;
      }
    xshow(PE->Memory, "Done.");

    // 平铺。
    if(!MappingDll(PE, DosHeader)) return false;

    // 远程重定位。
    if(!DoRelocation(PE)) return false;

    // 填写导入表。
    if(!DoImportTable(PE)) return false;

    // TLS
    if(!DoExecuteTLS(PE)) return false;

    // 设置文件加载基址。
    const auto offset = (size_t)&(NtHeaders.OptionalHeader.ImageBase) - (size_t)&DosHeader;
    const auto pImageBase = (void*)((size_t)PE->Memory + offset);
    xlog() << "SetImageBase...\r\n    ";
    if(FALSE == WriteProcessMemory(Process->hHandle, pImageBase, &PE->Memory, sizeof(PE->Memory), nullptr))
      {
      xshowerr("Fail");
      return false;
      }
    xlog() << "Done.\r\n";

    // 运行入口函数。
    if(!DoDllMain(PE)) return false;

    PE->hold();
    xshow(PE->Memory, "Done @");

    return true;
    }
  catch(...)
    {
    xlog() << "\r\n" xfunexpt "\r\n";
    return false;
    }
  }