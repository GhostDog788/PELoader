/*
* This is an implementation of the Windows SEH Mechanism. Including the SEH dispatcher in ntdll dispatcher,
* The CRT personality routine (which implements support for __try/__except/__finally) defined in chandler4.c,
* and the low level unwinder RtlUnwind defined in ntdll.
* 
* The Problem: There are several restrictions for SEH handlers in x86:
* 1. They must be located at a registered module.
*    The virtual memory they reside in must have the flag MEM_IMAGE which is stored in the kernel
*    object for the virtual memory section. This flag is set for images mapped by the windows loader.
* 2. SafeSEH tables enforce declining any unregistered handlers.
*    This restriction will not affect us as we don't add new handlers.
* 3. The MSVC _except_handler4 which handles the __try/__except/__finally blocks,
*    calls RtlUnwind when handling an exception. RtlUnwind calls RtlIsValidHandler which checks
*    the MEM_IMAGE flag again and catches us.
* Our module will never be registered in the os and thus will miss the MEM_IMAGE flag.
* 
* The Solution: We will reimplement _except_handler4 to use our own implementation 
* of RtlUnwind, without the RtlIsValidHandler call, in a vectored exception handler.
* This way we can handle SEH exceptions without passing through RtlUnwind, and in tern RtlIsValidHandler.
* This means we implement the whole dispatcher logic by ourselves, based on the CRT sources.
* This approach was used way back by the developers of JIT engines like .NET and Java, to add
* exception handling to their dynamically allocated executable memory.
*/
#pragma once
#ifndef _WIN64
#include <windows.h>
#include "InternalStructs.h"

// Use this function to enable SEH support inside VEH. Handles ALL SEH exceptions through our VEH handler.
// Optionally, hand over an address range list of modules to handle SEH only for them.
void EnableSEHoverVEH();

void DisableSEHoverVEH();

// A VEH handler that fully handles SEH exceptions with our _except_handler5.
_declspec(noreturn) VOID CALLBACK ShadowDispatchStructuredException(PEXCEPTION_POINTERS ExceptionInfo);

EXCEPTION_DISPOSITION NTAPI NestedExceptionHandler(EXCEPTION_RECORD* ExceptionRecord, PLONG pEstablisherFrame, CONTEXT* ContextRecord, PLONG pDispatcherContext);
EXCEPTION_REGISTRATION* GetRegistrationHead();

// Personality routine that handles __try/__except/__finally blocks.
DECLSPEC_GUARD_SUPPRESS
EXCEPTION_DISPOSITION _except_handler5(
    IN PEXCEPTION_RECORD                ExceptionRecord,
    IN PEXCEPTION_REGISTRATION_RECORD   EstablisherFrame,
    IN OUT PCONTEXT                     ContextRecord,
    IN OUT PVOID                        DispatcherContext,
	IN PUINT_PTR                        CookiePointer
);

// Low level unwinder that does not check for MEM_IMAGE flag.
VOID RtlUnwindUnSafe(
    IN PEXCEPTION_REGISTRATION TargetFrame,
    IN PVOID TargetIp,
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN DWORD ReturnValue,
    DWORD _esp
);

#endif