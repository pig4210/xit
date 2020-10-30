#include "UpperToken.h"

#include "xhandle.h"

bool UpperToken()
	{
  xlog() << __FUNCTION__ "...\r\n    ";

  xhandle Token;
	if(FALSE == OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token.hHandle))
    {
    xshowerr("OpenProcessToken Fail");
    return false;
    }
  LUID luid;
  if(FALSE == LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
    {
    xshowerr("LookupPrivilegeValue Fail");
    return false;
    }
  TOKEN_PRIVILEGES tkp;
  tkp.PrivilegeCount = 1;
  tkp.Privileges[0].Luid = luid;
  tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  if(FALSE == AdjustTokenPrivileges(Token, FALSE, &tkp, sizeof(tkp), nullptr, nullptr))
    {
    xshowerr("AdjustTokenPrivileges Fail");
    return false;
    }
  xlog() << "Done.\r\n";
  return true;
	}