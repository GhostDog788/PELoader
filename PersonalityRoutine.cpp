#ifndef _WIN64
#include "ShadowSEH.h"


// This is used for destructing the cpp object of the exception. Haven't implemented that
// Would require reimplementing DestructExceptionObject
//#pragma warning(disable: 4132)  // communal object is intentionally const
//void(__cdecl* const _pDestructExceptionObject)(
//    PEXCEPTION_RECORD   pExcept,
//    int                 fThrowNotAllowed
//    );

#define EH_EXCEPTION_NUMBER ('msc' | 0xE0000000)

LONG __fastcall _EH4_CallFilterFunc(
    _In_ PEXCEPTION_FILTER_X86  FilterFunc, // ecx
    _In_ PCHAR                  FramePointer // edx
)
{
    __asm {
        push ebp
        push esi
        push edi
        push ebx
        mov ebp, edx // change stack to start of try. so local vars are accessible from the filter expression 
        xor eax, eax
        xor ebx, ebx
        xor edx, edx
        xor esi, esi
        xor edi, edi
        call ecx // call FilterFunc with pushed params
        pop ebx
        pop edi
        pop esi
        pop ebp
    }
}

__declspec(naked)
__declspec(noreturn)
void __fastcall _EH4_TransferToHandler(
    _In_ PEXCEPTION_HANDLER_X86 HandlerAddress, // ecx
    _In_ PCHAR                  FramePointer // edx
)
{
    // Optional TODO: Implement _NLG_Notify for debugger notification
    __asm {
        mov ebp, edx
        mov esp, dword ptr[edx - 0x18]   // savedEsp (frame - 0x4 * 6)

        xor eax, eax
        xor ebx, ebx
        xor edx, edx
        xor esi, esi
        xor edi, edi
        // jump into handler (noreturn)
        jmp ecx
    }
}

__declspec(naked) void __fastcall _EH4_GlobalUnwind2(
    _In_opt_ PEXCEPTION_REGISTRATION_RECORD  EstablisherFrame, // ecx
    _In_opt_ PEXCEPTION_RECORD               ExceptionRecord // edx
)
{
    __asm {
        // ---- save full volatile state ----
        pushad  // push EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI (saves ECX/EDX too)
        pushfd  // push EFLAGS

        // Call RtlUnwindUnSafe
		push esp // added param so we can restore ESP in RtlUnwindUnSafe
        push dword ptr 0 // ReturnValue = NULL
        push edx  // ExceptionRecord
        push offset ReturnPoint_0  // TargetIp
        push ecx  // TargetFrame (EstablisherFrame)

        call RtlUnwindUnSafe

        ReturnPoint_0 :
        // ---- restore full volatile state ----
        popfd  // restore EFLAGS
        popad  // restore registers (including ESP restored to pre-pushad)
        ret
    }
}

void __fastcall _EH4_LocalUnwind(
    _In_ PEXCEPTION_REGISTRATION_RECORD  EstablisherFrame,
    _In_ ULONG                           TargetLevel,
    _In_ PCHAR                           FramePointer,
    _In_ PUINT_PTR                       CookiePointer
)
{
	// We can also use the exported function _local_unwind4 from msvcrt.dll if available.
#ifdef DEBUG
    HMODULE h_msvcrt = GetModuleHandleW(L"vcruntime140d.dll");
#else
    HMODULE h_msvcrt = GetModuleHandleW(L"vcruntime140.dll");
#endif // DEBUG

    if (h_msvcrt != nullptr) {
        auto address = GetProcAddress(h_msvcrt, "_local_unwind4");
        if (address != nullptr) {
            auto _local_unwind4 = reinterpret_cast<void(*)(PUINT_PTR, PEXCEPTION_REGISTRATION_RECORD, ULONG)>(address);
			_local_unwind4(CookiePointer, EstablisherFrame, TargetLevel);
            return;
        }
    }

	// Unwind to TargetLevel by calling all __finally blocks in between
	PEH4_EXCEPTION_REGISTRATION_RECORD RegistrationNode;
	PEH4_SCOPETABLE                     ScopeTable;
	ULONG                               TryLevel;
	ULONG                               EnclosingLevel;
	PEH4_SCOPETABLE_RECORD              ScopeTableRecord;
	PTERMINATION_HANDLER_X86            TerminationHandler;
	RegistrationNode =
		(PEH4_EXCEPTION_REGISTRATION_RECORD)
		((PCHAR)EstablisherFrame -
			FIELD_OFFSET(EH4_EXCEPTION_REGISTRATION_RECORD, SubRecord));
	ScopeTable = (PEH4_SCOPETABLE)
		(RegistrationNode->EncodedScopeTable ^ *CookiePointer);
	for (TryLevel = RegistrationNode->TryLevel;
		TryLevel != TOPMOST_TRY_LEVEL && TryLevel != TargetLevel;
		TryLevel = EnclosingLevel)
	{
		ScopeTableRecord = &ScopeTable->ScopeRecord[TryLevel];
		TerminationHandler = (PTERMINATION_HANDLER_X86)ScopeTableRecord->u.HandlerAddress;
		EnclosingLevel = ScopeTableRecord->EnclosingLevel;
		if (TerminationHandler != NULL)
		{
			// Call the __finally handler with TRUE to indicate unwind
			TerminationHandler(TRUE);
		}
	}
	RegistrationNode->TryLevel = TargetLevel;
}

#pragma warning(disable: 4100)  // ignore unreferenced formal parameters

/***
*_except_handler5 - actual SEH implementation with no gs checks. uses our own RtlUnwind
*
*Purpose:
*   Implement structured exception handling for functions which have __try/__except/__finally.
*
*   Call exception and termination handlers as necessary, based on the current
*   execution point within the function.
*
*Entry:
*   ExceptionRecord - pointer to the exception being dispatched
*   EstablisherFrame - pointer to the on-stack exception registration record
*       for this function
*   ContextRecord - pointer to a context record for the point of exception
*   DispatcherContext - pointer to the exception dispatcher or unwind
*       dispatcher context
*
*Return:
*   If an exception is being dispatched and the exception is handled by an
*   __except filter for this exception frame, then this function does not
*   return.  Instead, it calls our RtlUnwind and transfers control to the __except
*   block corresponding to the accepting __except filter.  Otherwise, an
*   exception disposition of continue execution or continue search is returned.
*
*   If an unwind is being dispatched, then each termination handler (__finally)
*   is called and a value of continue search is returned.
*
*******************************************************************************/

DECLSPEC_GUARD_SUPPRESS
EXCEPTION_DISPOSITION
_except_handler5(
        IN PEXCEPTION_RECORD                ExceptionRecord,
        IN PEXCEPTION_REGISTRATION_RECORD   EstablisherFrame,
        IN OUT PCONTEXT                     ContextRecord,
        IN OUT PVOID                        DispatcherContext,
        IN PUINT_PTR                        CookiePointer
    )
{
    PEH4_EXCEPTION_REGISTRATION_RECORD  RegistrationNode;
    PCHAR                               FramePointer;
    PEH4_SCOPETABLE                     ScopeTable;
    ULONG                               TryLevel;
    ULONG                               EnclosingLevel;
    EXCEPTION_POINTERS                  ExceptionPointers;
    PEH4_SCOPETABLE_RECORD              ScopeTableRecord;
    PEXCEPTION_FILTER_X86               FilterFunc;
    LONG                                FilterResult;
    BOOLEAN                             Revalidate = FALSE;
    EXCEPTION_DISPOSITION               Disposition = ExceptionContinueSearch;

    //ExceptionRecord->ExceptionCode = _filter_x86_sse2_floating_point_exception(ExceptionRecord->ExceptionCode);

    //
    // We are passed a registration record which is a field offset from the
    // start of our true registration record.
    //

    RegistrationNode =
        (PEH4_EXCEPTION_REGISTRATION_RECORD)
        ((PCHAR)EstablisherFrame -
            FIELD_OFFSET(EH4_EXCEPTION_REGISTRATION_RECORD, SubRecord));

    //
    // The EBP frame pointer in the function corresponding to the registration
    // record will be immediately following the record.  If the function uses
    // FPO, this is a "virtual" frame pointer outside of exception handling,
    // but it's still the EBP value set when calling into the handlers or
    // filters.
    //

    FramePointer = (PCHAR)(RegistrationNode + 1);

    //
    // Retrieve the scope table pointer, which encodes where we find the local
    // security cookies within the function's frame, as well as how the guarded
    // blocks in the target function are laid out.  This pointer was XORed with
    // the image-local global security cookie when originally stored, to avoid
    // attacks which spoof the table to address valid local cookies elsewhere
    // on the stack.
    //

    ScopeTable = (PEH4_SCOPETABLE)
        (RegistrationNode->EncodedScopeTable ^ *CookiePointer);

    //
    // Locals have been initiated, begin actual exception handling.
    //

    if (IS_DISPATCHING(ExceptionRecord->ExceptionFlags))
    {
        //
        // An exception dispatch is in progress.  First build the
        // EXCEPTION_POINTERS record queried by the _exception_info intrinsic
        // and save it in the exception registration record so the __except
        // filter can find it.
        //

        ExceptionPointers.ExceptionRecord = ExceptionRecord;
        ExceptionPointers.ContextRecord = ContextRecord;
        RegistrationNode->ExceptionPointers = &ExceptionPointers;

        //
        // Scan the scope table and call the appropriate __except filters until
        // we find one that accepts the exception.
        //

        for (TryLevel = RegistrationNode->TryLevel;
            TryLevel != TOPMOST_TRY_LEVEL;
            TryLevel = EnclosingLevel)
        {
            ScopeTableRecord = &ScopeTable->ScopeRecord[TryLevel];
            FilterFunc = ScopeTableRecord->FilterFunc;
            EnclosingLevel = ScopeTableRecord->EnclosingLevel;

            if (FilterFunc != NULL)
            {
                //
                // The current scope table record is for an __except.
                // Call the __except filter to see if we've found an
                // accepting handler.
                //

                FilterResult = _EH4_CallFilterFunc(FilterFunc, FramePointer);
                Revalidate = TRUE;

                //
                // If the __except filter returned a negative result, then
                // dismiss the exception.  If it returned a positive result,
                // unwind to the accepting exception handler.  Otherwise keep
                // searching for an exception filter.
                //

                if (FilterResult < 0)
                {
                    Disposition = ExceptionContinueExecution;
                    break;
                }
                else if (FilterResult > 0)
                {
                    //
                    // If we're handling a thrown C++ exception, let the C++
                    // exception handler destruct the thrown object.  This call
                    // is through a function pointer to avoid linking to the
                    // C++ EH support unless it's already present.  Don't call
                    // the function pointer unless it's in read-only memory.
                    //

                    //if (ExceptionRecord->ExceptionCode == EH_EXCEPTION_NUMBER &&
                    //    _pDestructExceptionObject != NULL &&
                    //    _IsNonwritableInCurrentImage((PBYTE)&_pDestructExceptionObject))
                    //{
                    //    (*_pDestructExceptionObject)(ExceptionRecord, TRUE);
                    //}

                    //
                    // Unwind all registration nodes below this one, then unwind
                    // the nested __try levels.
                    //
                    _EH4_GlobalUnwind2(
                        &RegistrationNode->SubRecord,
                        ExceptionRecord
                    );


                    if (RegistrationNode->TryLevel != TryLevel)
                    {
                        _EH4_LocalUnwind(
                            &RegistrationNode->SubRecord,
                            TryLevel,
                            FramePointer,
						    CookiePointer
                        );
                    }

                    //
                    // Set the __try level to the enclosing level, since it is
                    // the enclosing level, if any, that guards the __except
                    // handler.
                    //

                    RegistrationNode->TryLevel = EnclosingLevel;

                    //
                    // Call the __except handler.  This call will not return.
                    // The __except handler will reload ESP from the
                    // registration record upon entry.  The EBP frame pointer
                    // for the handler is directly after the registration node.
                    //

                    _EH4_TransferToHandler(
                        ScopeTableRecord->u.HandlerAddress,
                        FramePointer
                    );
                }
            }
        }
    }
    else
    {
        //
        // An exception unwind is in progress, and this isn't the target of the
        // unwind.  Unwind any active __try levels in this function, calling
        // the applicable __finally handlers.
        //

        if (RegistrationNode->TryLevel != TOPMOST_TRY_LEVEL)
        {
            _EH4_LocalUnwind(
                &RegistrationNode->SubRecord,
                TOPMOST_TRY_LEVEL,
                FramePointer,
		        CookiePointer
            );
            Revalidate = TRUE;
        }
    }

    //
    // Continue searching for exception or termination handlers in previous
    // registration records higher up the stack, or resume execution if we're
    // here because an __except filter returned a negative result.
    //

    return Disposition;
}

#endif // _WIN64