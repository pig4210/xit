#ifndef _XMSG_H_
#define _XMSG_H_

#include <string>
#include <cstdio>
#include <cstdarg>

// 简化版 xmsg 。
class xmsg : public std::string
  {
  public:
    xmsg() {}
  public:
    /// 指定格式输出。
    xmsg& prt(const char* const fmt, ...)
      {
      if(nullptr == fmt) return *this;
      va_list ap;
      va_start(ap, fmt);
      const auto need = std::vsnprintf(nullptr, 0, fmt, ap);
      if(0 >= need) return *this;
      std::string buffer;
      buffer.resize(need);
      std::vsnprintf(buffer.data(), buffer.size() + 1, fmt, ap);
      append(buffer);
      return *this;
      }
    /// 输出 dec 值。
    xmsg& operator<<(const int8_t& v)
      {
      return prt("%hhi", v);
      }
    /// 输出 hex(XX)。
    xmsg& operator<<(const uint8_t& v)
      {
      return prt("%02X", v);
      }
    /// 输出 dec 值。
    xmsg& operator<<(const int16_t& v)
      {
      return prt("%hi", v);
      }
    /// 输出 hex(XXXX)。
    xmsg& operator<<(const uint16_t& v)
      {
      return prt("%04X", v);
      }
    /// 输出 dec 值。
    xmsg& operator<<(const int32_t& v)
      {
      return prt("%i", v);
      }
    /// 输出 hex(XXXXXXXX)。
    xmsg& operator<<(const uint32_t& v)
      {
      return prt("%08X", v);
      }
    /// 输出 dec 值。
    xmsg& operator<<(const int64_t& v)
      {
      return prt("%lli", v);
      }
    /// 输出 hex(XXXXXXXXXXXXXXXX)。
    xmsg& operator<<(const uint64_t& v)
      {
      return prt("%08X%08X", (uint32_t)(v >> (CHAR_BIT * sizeof(uint32_t))), (uint32_t)v);
      }
    /// 输出 hex 指针。
    xmsg& operator<<(const void* const v)
      {
      return operator<<((size_t)v);
      }
    /// 输出 :true :false。
    xmsg& operator<<(const bool& v)
      {
      return operator<<(v ? L":true" : L":false");
      }
    /// 输出 ANSI 字符 转换 UNICCODE 字符。
    xmsg& operator<<(const char& v)
      {
      push_back(v);
      return *this;
      }
    /// 输出 ANSI 字符串 转换 UNICCODE 字符串。
    xmsg& operator<<(const char* const v)
      {
      if(nullptr != v) append(v);
      return *this;
      }
    /// 输出 ASNI 字符串 转换 UNICCODE 字符串。
    xmsg& operator<<(const std::string& v)
      {
      append(v);
      return *this;
      }
    /// 输出 dec 浮点数。
    xmsg& operator<<(const float& v)
      {
      return prt("%f", v);
      }
    /// 输出 dec 浮点数。
    xmsg& operator<<(const double& v)
      {
      return prt("%f", v);
      }
    /// 输出 内容。
    xmsg& operator<<(const xmsg& v)
      {
      append(v);
      return *this;
      }
  public:
    xmsg& operator<<(const long& v)
      {
      return operator<<((int32_t)v);
      }
    xmsg& operator<<(const unsigned long& v)
      {
      return operator<<((uint32_t)v);
      }
  };

#endif  // _XMSG_H_