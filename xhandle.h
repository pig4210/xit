#ifndef _XHANDLE_H_
#define _XHANDLE_H_

#include "xlog.h"

// 封装对象用于自动释放句柄。
class xhandle
  {
  public:
    xhandle(HANDLE h = nullptr):hHandle(h)
      {
      }
    ~xhandle()
      {
      if(INVALID_HANDLE_VALUE == hHandle) return;
      if(nullptr == hHandle) return;
      // xshow(hHandle, "CloseHandle");
      CloseHandle(hHandle);
      }
    operator HANDLE() const
      {
      return hHandle;
      }
    operator bool() const
      {
      return (INVALID_HANDLE_VALUE != hHandle) && (nullptr != hHandle);
      }
  public:
    xhandle(const xhandle&) = delete;
    xhandle& operator=(const xhandle&) = delete;
  public:
    HANDLE hHandle;
  };

#endif  //_XHANDLE_H_