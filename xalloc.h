#ifndef _XALLOC_H_
#define _XALLOC_H_

#include <memory>

#include "xhandle.h"

// 封装对象用于自动释放空间。
class xalloc
  {
  public:
    xalloc(std::shared_ptr<xhandle>& p, void* m):Process(p), Memory(m), holded(false)
      {
      }
    ~xalloc()
      {
      if(nullptr == Memory) return;
      if(holded == true) return;
      // xshow(Memory, "VirtualFreeEx");
      VirtualFreeEx(Process->hHandle, Memory, 0, MEM_RELEASE);
      }
    void hold(const bool h = true)
      {
      holded = h;
      }
    operator void*() const
      {
      return Memory;
      }
    operator bool() const
      {
      return nullptr != Memory;
      }
  public:
    xalloc(const xalloc&) = delete;
    xalloc& operator=(const xalloc&) = delete;
  public:
    std::shared_ptr<xhandle> Process;
    void* Memory;
    bool holded;
  };

#endif  //_XALLOC_H_