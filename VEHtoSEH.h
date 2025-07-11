#ifndef _WIN64
#ifndef SEHX86_MOD
#define SEHX86_MOD

#include <windows.h>

_declspec(noreturn) VOID CALLBACK DispatchStructuredException(PEXCEPTION_POINTERS ExceptionInfo);

#endif
#endif