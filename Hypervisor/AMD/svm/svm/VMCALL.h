#pragma once
#ifndef VMCALL_H
#define VMCALL_H
#include <ntifs.h>


extern "C" ULONG64 __fastcall Hypercall(ULONG64 Code, ULONG64 Arg1, ULONG64 Arg2, ULONG64 Arg3);


#endif