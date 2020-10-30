#ifndef _XLOG_H_
#define _XLOG_H_

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "xmsg.h"

/// 允许改变 xlog 默认输出行为。
#ifdef XSTDCOUT
#include <iostream>
#define XLOGOUT(msg) std::cout << (msg);
#else
#define XLOGOUT(msg) OutputDebugStringA(msg);
#endif

class xlog : public xmsg
  {
  public:
    enum xlog_level
      {
      off,    ///< 屏蔽输出。
      fatal,  ///< 致命错误，程序无法继续执行。
      error,  ///< 反映错误，例如一些 API 的调用失败。
      warn,   ///< 反映某些需要注意的可能有潜在危险的情况，可能会造成崩溃或逻辑错误之类。
      info,   ///< 表示程序进程的信息。
      debug,  ///< 普通的调试信息，这类信息发布时一般不输出。
      trace,  ///< 最精细的调试信息，多用于定位错误，查看某些变量的值。
      on,     ///< 全输出。
      };
  public:
    virtual ~xlog()
      {
      do_out();
      }
    xlog& do_out()
      {
      if(empty())  return *this;
      XLOGOUT(c_str());
      clear();
      return *this;
      }
  };

#ifndef xlog_static_lvl
#define xlog_static_lvl xlog::on
#endif

#define xlog_do(v) if constexpr ((v) <= xlog_static_lvl) xlog()

#define xtrace  xlog_do(xlog::trace)
#define xdbg    xlog_do(xlog::debug)
#define xinfo   xlog_do(xlog::info)
#define xwarn   xlog_do(xlog::warn)
#define xerr    xlog_do(xlog::error)
#define xfail   xlog_do(xlog::fatal)

#define xfuninfo "[" __FUNCTION__ "][" << __LINE__ << "]: "
#define xfunexpt "[" __FUNCTION__ "]: exception."

template<class T>
void xshow(const T& v, const char* prefix = nullptr, const char* suffix = nullptr)
  {
  if(nullptr != prefix) xlog() << prefix << " : ";
  if constexpr (std::is_same_v<void*, T>)
    {
    xlog() << v << '(' << (std::make_signed_t<size_t>)v << ")\r\n";
    }
  else
    {
    xlog() << (std::make_unsigned_t<T>)v << '(' << (std::make_signed_t<T>)v << ")\r\n";
    }
  if(nullptr != suffix) xlog() << suffix;
  }

void inline xshowerr(const char* msg)
  {
  xshow(GetLastError(), msg);
  }

#endif  // _XLOG_H_