#pragma once

#include "ShadowSEH.h"
#include <WinNT.h>
#include <excpt.h>


// from \crt\src\eh\i386\trnsctrl.cpp
#define EXCEPTION_UNWINDING 0x2         /* Unwind is in progress */
#define EXCEPTION_EXIT_UNWIND 0x4       /* Exit unwind is in progress */
#define EXCEPTION_STACK_INVALID 0x8     /* Stack out of limits or unaligned */
#define EXCEPTION_NESTED_CALL 0x10      /* Nested exception handler call */
#define EXCEPTION_TARGET_UNWIND 0x20    /* Target unwind in progress */
#define EXCEPTION_COLLIDED_UNWIND 0x40  /* Collided exception handler call */

extern "C" NTSYSAPI VOID NTAPI RtlRaiseException(PEXCEPTION_RECORD ExceptionRecord);
extern "C" NTSYSAPI NTSTATUS NTAPI NtContinue(IN PCONTEXT ThreadContext, IN BOOLEAN RaiseAlert);
extern "C" NTSYSAPI NTSTATUS NTAPI NtRaiseException(IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT ThreadContext, IN BOOLEAN HandleException);

#define EXCEPTION_UNWIND (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND | \
                          EXCEPTION_TARGET_UNWIND | EXCEPTION_COLLIDED_UNWIND)

#define IS_UNWINDING(Flag) ((Flag & EXCEPTION_UNWIND) != 0)
#define IS_DISPATCHING(Flag) ((Flag & EXCEPTION_UNWIND) == 0)
#define IS_TARGET_UNWIND(Flag) (Flag & EXCEPTION_TARGET_UNWIND)


/*
 * Define __except filter/handler and __finally handler function types.
 */

typedef LONG(__cdecl* PEXCEPTION_FILTER_X86)(void);
typedef void(__cdecl* PEXCEPTION_HANDLER_X86)(void);
typedef void(__fastcall* PTERMINATION_HANDLER_X86)(BOOL);

/*
 * The function-specific scope table pointed to by the on-stack exception
 * registration record.  This describes the nesting structure of __try blocks
 * in the function, the location of all __except filters, __except blocks, and
 * __finally blocks, and the data required to check the security cookies in
 * the function
 */

typedef struct _EH4_SCOPETABLE_RECORD
{
    ULONG                           EnclosingLevel;
    PEXCEPTION_FILTER_X86           FilterFunc;
    union
    {
        PEXCEPTION_HANDLER_X86      HandlerAddress;
        PTERMINATION_HANDLER_X86    FinallyFunc;
    } u;
} EH4_SCOPETABLE_RECORD, * PEH4_SCOPETABLE_RECORD;

typedef struct _EH4_SCOPETABLE
{
    ULONG                       GSCookieOffset;
    ULONG                       GSCookieXOROffset;
    ULONG                       EHCookieOffset;
    ULONG                       EHCookieXOROffset;
    EH4_SCOPETABLE_RECORD       ScopeRecord[1];
} EH4_SCOPETABLE, * PEH4_SCOPETABLE;

#define TOPMOST_TRY_LEVEL   ((ULONG)-2)

/*
 * The exception registration record stored in the stack frame.  The linked
 * list of registration records goes through the EXCEPTION_REGISTRATION_RECORD
 * sub-struct, so some fields here are at negative offsets with regards to
 * the registration record pointer we are passed.
 */

typedef struct _EH4_EXCEPTION_REGISTRATION_RECORD
{
    PVOID                           SavedESP;
    PEXCEPTION_POINTERS             ExceptionPointers;
    EXCEPTION_REGISTRATION_RECORD   SubRecord;
    UINT_PTR                        EncodedScopeTable;
    ULONG                           TryLevel;
} EH4_EXCEPTION_REGISTRATION_RECORD, * PEH4_EXCEPTION_REGISTRATION_RECORD;

typedef struct EXCEPTION_REGISTRATION
{
    EXCEPTION_REGISTRATION* nextframe;
    PEXCEPTION_ROUTINE handler;
} *PEXCEPTION_REGISTRATION;
