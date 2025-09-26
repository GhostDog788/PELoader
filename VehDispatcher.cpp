#ifndef _WIN64
#include "InternalStructs.h"
#include <iostream>
#include "ShadowSEH.h"

_declspec(naked) EXCEPTION_REGISTRATION* GetRegistrationHead()
{
	__asm mov eax, dword ptr fs : [0]
		__asm retn
}

void EnableSEHoverVEH()
{
	AddVectoredExceptionHandler(0, (PVECTORED_EXCEPTION_HANDLER)&ShadowDispatchStructuredException);
}

void DisableSEHoverVEH()
{
	RemoveVectoredExceptionHandler(ShadowDispatchStructuredException);
	// there may be several instances of this handler registered so I don't know how the remove function will handle that
}

bool IsReadable(void* addr) {
	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQuery(addr, &mbi, sizeof(mbi)))
		return false;

	// Must be committed memory
	if (mbi.State != MEM_COMMIT)
		return false;

	// Must have read access
	DWORD protect = mbi.Protect & 0xff;
	if (protect == PAGE_NOACCESS || protect == PAGE_EXECUTE)
		return false;

	return true;
}

PUINT_PTR getGSCookiePointerFromHandler(PEXCEPTION_ROUTINE except_handler4_address)
{
	unsigned char* func = reinterpret_cast<unsigned char*>(except_handler4_address);
	return  reinterpret_cast<PUINT_PTR>(*reinterpret_cast<PUINT_PTR>(func + 0x20));
}

EXCEPTION_DISPOSITION NTAPI NestedExceptionHandler(EXCEPTION_RECORD* ExceptionRecord, PLONG pEstablisherFrame, CONTEXT* ContextRecord, PLONG pDispatcherContext)
{
	if (ExceptionRecord->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND))
		return ExceptionContinueSearch;
	else
	{
		*pDispatcherContext = *(pEstablisherFrame + 2); /* move previously saved EstablisherFrame from [pEstablisherFrame+8h] */
		return ExceptionNestedException;
	}
}

EXCEPTION_DISPOSITION SafeExecuteMyHandler(EXCEPTION_RECORD* ExceptionRecord, PVOID EstablisherFrame, CONTEXT* ContextRecord, PVOID DispatcherContext, PEXCEPTION_ROUTINE pHandler)
{
	__asm {
		/*
			An additional frame to catch nested exception, also for running __cdecl/__stdcall handlers correctly.

			If you use C++ exceptions - leave this as is, when C++ exception will be catched
			unwinding will be done in MSVCR._UnwindNestedFrames (check developer's commentaries
			in \crt\src\eh\i386\trnsctrl.cpp and view _JumpToContinuation)
		*/
		push	EstablisherFrame        /* save EstablisherFrame for nested exception */
		push	NestedExceptionHandler
		push	dword ptr fs : [0]
		mov		dword ptr fs : [0] , esp
	}
	EXCEPTION_DISPOSITION Disposition;
	auto cookiePointer = getGSCookiePointerFromHandler(pHandler);
	std::cout << "Handler: " << std::hex << (void*)pHandler << std::dec << std::endl;
	if (IsReadable(cookiePointer)) {
		std::cout << "GSCookiePointer: " << std::hex << cookiePointer << std::dec << std::endl;
		std::cout << "GSCookie: " << std::hex << *cookiePointer << std::dec << std::endl;
		Disposition = _except_handler5(ExceptionRecord, (PEXCEPTION_REGISTRATION_RECORD)EstablisherFrame, ContextRecord, DispatcherContext, cookiePointer);
	}
	else {
		Disposition = pHandler(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
	}
	__asm {
		mov		esp, dword ptr fs : [0]
		pop		dword ptr fs : [0]
		add     esp, 8                  /* restore stack to prevent esi/edi corruption */
	}
	return Disposition;
}

_declspec(noreturn) VOID CALLBACK ShadowDispatchStructuredException(PEXCEPTION_POINTERS ExceptionInfo)
{
	PCONTEXT ctx = ExceptionInfo->ContextRecord;
	PEXCEPTION_RECORD ex = ExceptionInfo->ExceptionRecord;
	PEXCEPTION_REGISTRATION Registration = GetRegistrationHead();
	PEXCEPTION_REGISTRATION NestedRegistration = 0, DispatcherContext = 0;

	while ((LONG)Registration != -1)    /* -1 means end of chain */
	{
		EXCEPTION_DISPOSITION Disposition = SafeExecuteMyHandler(ex, Registration, ctx, &DispatcherContext, Registration->handler);

		if (NestedRegistration == Registration)
		{
			ex->ExceptionFlags &= (~EXCEPTION_NESTED_CALL);
			NestedRegistration = 0;
		}

		switch (Disposition)
		{
			EXCEPTION_RECORD nextEx;

		case ExceptionContinueExecution:
			if (!(ex->ExceptionFlags & EXCEPTION_NONCONTINUABLE))
				NtContinue(ctx, 0);
			else
			{
				nextEx.ExceptionCode = EXCEPTION_NONCONTINUABLE_EXCEPTION;
				nextEx.ExceptionFlags = 1;
				nextEx.ExceptionRecord = ex;
				nextEx.ExceptionAddress = 0;
				nextEx.NumberParameters = 0;
				RtlRaiseException(&nextEx);
			}
			break;

		case ExceptionContinueSearch:
			if (ex->ExceptionFlags & EXCEPTION_STACK_INVALID)
				NtRaiseException(ex, ctx, false);
			break;

		case ExceptionNestedException:
			ex->ExceptionFlags |= EXCEPTION_NESTED_CALL;
			// renew context
			if (DispatcherContext > NestedRegistration)
				NestedRegistration = DispatcherContext;
			break;

		default:
			nextEx.ExceptionRecord = ex;
			nextEx.ExceptionCode = STATUS_INVALID_DISPOSITION;
			nextEx.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
			nextEx.NumberParameters = 0;
			RtlRaiseException(&nextEx);
			break;
		}
		Registration = Registration->prev;
	}

	/*
		dispatcher hasn't found appropriate hander for exception in SEH chain,
		if this handler was first in the VEH-chain - there are could be other vectored handlers,
		those handlers needs to take a chance to handle this exception (return EXCEPTION_CONTINUE_SEARCH;).
		if this handler is first - just call: NtRaiseException(ex, ctx, false);
	*/
	NtRaiseException(ex, ctx, false);
}

#endif