#include <iostream>
#include <string>
#include <fstream>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Tlhelp32.h>

#include "xhandle.h"
#include "UpperToken.h"
#include "xDll.h"

static void Usage(const std::wstring& path)
  {
  wchar_t name[_MAX_FNAME];
  _wsplitpath_s(path.c_str(), nullptr, 0, nullptr, 0, name, sizeof(name), nullptr, 0);
  std::cout << std::endl << "USAGE : " << std::endl << std::endl;
  std::wcout << L"    LoadDll   :      " << name << L"   ProcessName  DllFileName" << std::endl;
  std::wcout << L"    LoadDll   :      " << name << L"   PID          DllFileName" << std::endl;
  std::wcout << L"    UnLoadDll :      " << name << L"   ProcessName  DllModule" << std::endl;
  std::wcout << L"    UnLoadDll :      " << name << L"   PID          DllModule" << std::endl;
  std::cout  << std::endl;
  }

static DWORD GetPID(const std::wstring& data)
  {
  xlog() << __FUNCTION__ "...\r\n    ";
  wchar_t* end = (wchar_t*)data.c_str();
  const auto PID = wcstoul(end, &end, 16);
  // 完全转换完成，并转换成功才行。
  if((size_t)(end - data.c_str()) == data.size() && 0 != PID && ULONG_MAX != PID)
    {
    xshow(PID, "Done");
    return PID;
    }
  
  xhandle Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if(!Snapshot)
    {
    xshowerr("CreateToolhelp32Snapshot Fail");
    return 0;
    }
  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(pe32);
  if(FALSE == Process32First(Snapshot, &pe32))
    {
    xshowerr("Process32First Fail");
    return 0;
    }

  do
    {
    if(0 == _wcsicmp(data.c_str(), pe32.szExeFile))
      {
      xshow(pe32.th32ProcessID, "Done");
      return pe32.th32ProcessID;
      }
    }while(Process32Next(Snapshot, &pe32));

  xlog() << "No PID!\r\n";
  return 0;
  }

static HMODULE GetModuleValue(const std::wstring& data)
  {
  wchar_t* end = (wchar_t*)data.c_str();
#ifdef _WIN64
  auto Mod = wcstoull(end, &end, 16);
  // 完全转换完成，并转换成功才行。
  if((size_t)(end - data.c_str()) == data.size() && 0 != Mod && ULLONG_MAX != Mod)
#else
  auto Mod = wcstoul(end, &end, 16);
  // 完全转换完成，并转换成功才行。
  if((size_t)(end - data.c_str()) == data.size() && 0 != Mod && ULONG_MAX != Mod)
#endif
    {
    if(Mod < 0x1000) Mod <<= 16;
    return (HMODULE)Mod;
    }
  return nullptr;
  }

static std::string ReadFile(const std::wstring& dllpath)
  {
  try
    {
    xlog() << __FUNCTION__ "...\r\n    ";

    std::wifstream file(dllpath, std::ios::in|std::ios::binary);
    if(!file)
      {
      xlog() << "Open Fail!\r\n";
      return std::string();
      }
    
    auto s = file.tellg();
    file.seekg(0, std::ios::end);
    auto e = file.tellg();
    file.seekg(0, std::ios::beg);

    const auto size = e - s;
    xshow(size, "File Size", "    ");

    std::wstring buffer;
    buffer.resize((size_t)size);
    file.read(buffer.data(), size);

    // 注意 wifstream 默认是一个 byte 按 一个 wchar_t 读取，故需转换。
    std::string dllfile;
    for(auto it = buffer.begin(); it != buffer.end(); ++it)
      {
      dllfile.push_back((char)*it);
      }
    xlog() << "Done.\r\n";
    return dllfile;
    }
  catch(...)
    {
    xlog() << "\r\n" xfunexpt "\r\n";
    return std::string();
    }
  }

int wmain(int argc, const wchar_t* argv[])
  {
  if(argc <= 1 || argc >= 4)
    {
    Usage(argv[0]);
    return 0;
    }
  
  UpperToken(); // 无论是否提权成功，都尝试继续。

  // 首先尝试把第二参认为 PID 。
  const auto PID = GetPID(argv[1]);
  if(0 == PID)  return 0;
  
  const auto hModule = GetModuleValue(argv[2]);
  if(nullptr == hModule)
    {
    // 读取 DLL 文件。
    const auto DllFile = ReadFile(argv[2]);
    if(DllFile.empty()) return 0;

    LoadLibraryW(PID, DllFile);
    }

  int a;
  std::cin >> a;
  return 0;
  }