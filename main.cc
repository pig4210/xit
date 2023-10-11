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
  if (argc <= 1) {
    // 因为测试用例需要创建进程，再次创建本 EXE ，所以不能简单地退出，否则 DLL 卸载时会出错。也不能 getch ，仍然太快，故这里做了个延时。
    std::cout << "Usage : xit  pid|process_name|exe_path  [dll_path]"  << std::endl;
    Sleep(1000);
    return 0;
  }

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

  HANDLE hProcess = nullptr;
  HANDLE hThread = nullptr;

  auto res = xit::GetPID(argv[1]);
  if (xit::IsOK(res)) {
    // 是 进程名 或 PID 。
    const auto pid = (DWORD)res;
    res = xit::OpenProcess(pid);
    if (!CheckOK(res)) return 0;
    hProcess = (HANDLE)res;  
  } else {
    // 认为是 exe 路径。创建进程，挂起。后续操作如有失败情况，进程会被终止。
    PROCESS_INFORMATION pi;
    res = xit::CreateProcess(argv[1], &pi);
    if (!CheckOK(res)) return 0;
    hProcess = pi.hProcess;
    hThread = pi.hThread;

    // 此块功能：等待 进程 完全加载。否则会注入失败的情况。
    res = xit::RemoteThread(hProcess, (LPTHREAD_START_ROUTINE)GetModuleHandle, nullptr);
    // 这里即使成功， res 也是失败的，需要区分检查。
    if (xit::XRemoteThread != xit::Error(res)) {
      CheckOK(res);
      CloseHandle(hThread);
      TerminateProcess(hProcess, 0);
      CloseHandle(hProcess);
      return 0;
    }
  }
  // 本来想要判断 进程 x64/x86 ，再判断 DLL 比较x64/x86 ，但意义不大，故先放弃。

  if (argc == 2) {
    // 参数不够，则加载内置资源。
    res = xit::LoadDll(hProcess, GetModuleHandle(nullptr), MAKEINTRESOURCE(RESID), TEXT("BIN"));
  } else {
    // 第三个参数，认为是 DLL 路径。
    res = xit::LoadDll(hProcess, argv[2]);
  }
  if (!CheckOK(res)) {
    if (nullptr != hThread) {
      CloseHandle(hThread);
      TerminateProcess(hProcess, 0);
    }
    CloseHandle(hProcess);
    return 0;
  }
  auto PE = (LPVOID)res;
  std::cout << "PE     : " << PE << std::endl;

  if (nullptr != hThread) {
    // 如果进程是创建挂起的，则恢复。
    ResumeThread(hThread);
    CloseHandle(hThread);
  }

  
  if (argc == 2) {
    // 内置资源，则测试查找导出函数。
    res = xit::RemoteDllProcAddr(hProcess, PE, "TestExport", false);
    std::cout << "Export : " << (void*)res << std::endl;
  }
  

  std::cout << "Press any key to free dll , or n to skip ..." << std::endl;
  const auto ch = _getch();

  if (ch == 'n' || ch == 'N') {
    CloseHandle(hProcess);
    return 0;
  }

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