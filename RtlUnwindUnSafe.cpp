#ifndef _WIN64
#include "ShadowSEH.h"

#define BAD_POINTER ((PVOID)-1)

EXCEPTION_DISPOSITION RtlpExecuteHandlerForUnwind(
	PEXCEPTION_RECORD ExceptionRecord,
	PEXCEPTION_REGISTRATION RegistrationFrame,
	PCONTEXT ContextRecord,
	PLONG pDispatcherContext,
	PEXCEPTION_ROUTINE ExceptionRoutine
) {
	return ExceptionRoutine(ExceptionRecord, RegistrationFrame, ContextRecord, pDispatcherContext);
}

void RtlpUnlinkHandler(PEXCEPTION_REGISTRATION pRegistrationFrame)
{
	__asm {
		mov eax, pRegistrationFrame   // load pointer argument
		mov eax, [eax]                // eax = pRegistrationFrame->prev
		mov fs:[0], eax               // restore previous registration
	}
}

void RtlpCaptureContext(PCONTEXT pContext)
{
	__asm {
		// Zero GP registers
		mov edx, pContext // edx = pointer to CONTEXT
		mov dword ptr[edx + CONTEXT.Eax], 0
		mov dword ptr[edx + CONTEXT.Ecx], 0
		mov dword ptr[edx + CONTEXT.Edx], 0
		mov dword ptr[edx + CONTEXT.Ebx], 0
		mov dword ptr[edx + CONTEXT.Esi], 0
		mov dword ptr[edx + CONTEXT.Edi], 0

		// Segment registers
		xor eax, eax
		mov ax, cs
		mov dword ptr[edx + CONTEXT.SegCs], eax

		mov ax, ds
		mov dword ptr[edx + CONTEXT.SegDs], eax

		mov ax, es
		mov dword ptr[edx + CONTEXT.SegEs], eax

		mov ax, fs
		mov dword ptr[edx + CONTEXT.SegFs], eax

		mov ax, gs
		mov dword ptr[edx + CONTEXT.SegGs], eax

		mov ax, ss
		mov dword ptr[edx + CONTEXT.SegSs], eax

		// Flags
		pushfd
		pop[edx + CONTEXT.EFlags]

		// Walk one frame up (caller’s caller)
		mov edx, [ebp] // saved EBP of caller
		mov[edx + CONTEXT.Ebp], edx

		mov ecx, [ebp + 4] // return address of caller’s caller
		mov[edx + CONTEXT.Eip], ecx

		lea ecx, [edx + 8] // ESP as if after prologue
		mov[edx + CONTEXT.Esp], ecx
	}
}

void RtlpGetStackLimits(DWORD* stackUserBase, DWORD* stackUserTop) {
	__asm {
		mov eax, fs:[4]  // Load stack base
		mov edx, stackUserBase
		mov dword ptr[edx], eax

		mov eax, fs:[8]  // Load stack top
		mov edx, stackUserTop
		mov dword ptr[edx], eax
	}
}

VOID RtlUnwindUnSafe(
    IN PEXCEPTION_REGISTRATION TargetFrame,
    IN PVOID TargetIp,
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN DWORD ReturnValue,
	DWORD _esp
) 
{
	DWORD stackUserBase;
	DWORD stackUserTop;
	CONTEXT context;

	// Get stack boundaries from FS:[4] and FS:[8]
	RtlpGetStackLimits(&stackUserBase, &stackUserTop);

	if (TargetFrame)
		ExceptionRecord->ExceptionFlags |= EXCEPTION_UNWINDING;
	else
		ExceptionRecord->ExceptionFlags |= (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND);

	context.ContextFlags = (CONTEXT_i486 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS);

	RtlpCaptureContext(&context);
	context.Eip = (DWORD)TargetIp;
	context.Esp = _esp;

	//context.Esp += 0x10;
	context.Eax = ReturnValue;

	PEXCEPTION_REGISTRATION pExcptRegHead = GetRegistrationHead();  // Retrieve FS:[0]

	// Begin traversing the list of EXCEPTION_REGISTRATION
	while (BAD_POINTER != pExcptRegHead)
	{
		EXCEPTION_RECORD error_record{0};

		if (pExcptRegHead == TargetFrame)
		{
			NtContinue(&context, 0);
		}
		// If there's an exception frame, but it's lower on the stack,
		// then the head of the exception list, something's wrong!
		else if (TargetFrame && (TargetFrame < pExcptRegHead))
		{
			// Generate an exception to bail out
			error_record.ExceptionRecord = ExceptionRecord;
			error_record.NumberParameters = 0;
			error_record.ExceptionCode = STATUS_INVALID_UNWIND_TARGET;
			error_record.ExceptionFlags = EXCEPTION_NONCONTINUABLE;

			RtlRaiseException(&error_record);
		}

		PVOID pStack = pExcptRegHead + 8; // sizeof(EXCEPTION_REGISTRATION);

		// Make sure that pExcptRegHead is in range, and a multiple of 4 (i.e., sane)
		if ((stackUserBase >= (DWORD)pExcptRegHead) && (stackUserTop <= (DWORD)pStack) && (0 == ((DWORD)pExcptRegHead & 3)))
		{
			PEXCEPTION_REGISTRATION pNewRegHead;
			EXCEPTION_DISPOSITION retValue;

			retValue = RtlpExecuteHandlerForUnwind(
				ExceptionRecord, pExcptRegHead, &context, (PLONG)&pNewRegHead, pExcptRegHead->handler);

			if (retValue != ExceptionContinueSearch)
			{
				if (retValue != ExceptionCollidedUnwind)
				{
					error_record.ExceptionRecord = ExceptionRecord;
					error_record.NumberParameters = 0;
					error_record.ExceptionCode = STATUS_INVALID_DISPOSITION;
					error_record.ExceptionFlags = EXCEPTION_NONCONTINUABLE;

					RtlRaiseException(&error_record);
				}
				else
					pExcptRegHead = pNewRegHead;
			}

			PEXCEPTION_REGISTRATION pCurrExcptReg = pExcptRegHead;
			pExcptRegHead = pExcptRegHead->prev;

			RtlpUnlinkHandler(pCurrExcptReg);
		}
		else    // The stack looks goofy!  Raise an exception to bail out
		{
			error_record.ExceptionRecord = ExceptionRecord;
			error_record.NumberParameters = 0;
			error_record.ExceptionCode = STATUS_BAD_STACK;
			error_record.ExceptionFlags = EXCEPTION_NONCONTINUABLE;

			RtlRaiseException(&error_record);
		}
	}

	// If we get here, we reached the end of the EXCEPTION_REGISTRATION list.
	// This shouldn't happen normally.

	if (BAD_POINTER == TargetFrame)
		NtContinue(&context, 0);
	else
		NtRaiseException(ExceptionRecord, &context, 0);

}

#endif // _WIN64