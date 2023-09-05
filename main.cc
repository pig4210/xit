#include <iostream>
#include <string>
#include <conio.h>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#undef NOMINMAX
#undef WIN32_LEAN_AND_MEAN

#include "xit.h"

static bool CheckOK(const xit::Result& res) {
  if (xit::IsOK(res)) return true;
  std::cout << "There is Error :" << std::endl;
  std::cout << "    " << (void*)xit::Error(res) << '(' << xit::Error(res) << ')' << std::endl;
  std::cout << "    " << (void*)(size_t)xit::ErrorEx(res) << '(' << xit::ErrorEx(res) << ')' << std::endl;
  return false;
}

int wmain(int argc, LPCTSTR argv[]) {
  if (argc <= 1) return 0;

  xit::UpperToken(GetCurrentProcess()); // 无论是否提权成功，都尝试继续。

  if (argc >= 3) {
    // 指定 HMODULE ，则卸载之。
    const auto res = xit::GetModule(argv[2]);
    if (xit::IsOK(res)) {
      auto PE = (LPVOID)res;
      const auto st = xit::UnloadDll(argv[1], PE);
      CheckOK(st.tls);
      CheckOK(st.main);
      CheckOK(st.import);
      CheckOK(st.ex);
      std::cout << "Done." << std::endl;
      _getch();
      return 0;
    }
  }

  auto res = xit::OpenProcess(argv[1]);
  if (!CheckOK(res)) return 0;
  auto hProcess = (HANDLE)res;

  if(argc == 2) {
    res = xit::LoadRes(GetModuleHandle(nullptr), MAKEINTRESOURCE(RESID), TEXT("BIN"));
  } else {
    res = xit::LoadFile(argv[2]);
  }
  if (!CheckOK(res)) {
    CloseHandle(hProcess);
    return 0;
  }
  auto hMem = (HLOCAL)res;
  res = xit::Mapping(hProcess, hMem);
  if (!CheckOK(res)) {
    CloseHandle(hProcess);
    LocalFree(hMem);
    return 0;
  }

  LocalFree(hMem);
  auto PE = (LPVOID)res;
  
  res = xit::LoadDll(hProcess, PE);
  if (!CheckOK(res)) {
    VirtualFreeEx(hProcess, PE, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return 0;
  }
  
  if (FALSE != IsBadReadPtr(PE, 1)) {
    CloseHandle(hProcess);
    std::cout << "Done." << (void*)PE << std::endl;
    return 0;
  }
  
  res = xit::RemoteDllProcAddr(hProcess, PE, "TestExport", false);
  std::cout << (void*)res << std::endl;

  std::cout << "Press any key to free dll..." << std::endl;
  _getch();

  const auto st = xit::UnloadDll(hProcess, PE, true);

  CloseHandle(hProcess);

  CheckOK(st.tls);
  CheckOK(st.main);
  CheckOK(st.import);
  CheckOK(st.ex);

  std::cout << "Done." << std::endl;
  _getch();
  return 0;
}