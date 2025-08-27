#pragma once
#include <ntifs.h>
#include <classpnp.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>
#pragma warning (disable : 4201) 
#pragma warning (disable : 4083) 
#pragma warning (disable : 4005) 
#pragma warning (disable : 4100)
#pragma warning (disable : 5040)
#pragma warning (disable : 4083)
#pragma warning (disable : 4996)
#include <intrin.h>
#include <stdint.h>

#define debug_log(text, ...) (DbgPrintEx(0, 0, /*xs*/(text), ##__VA_ARGS__))

#define debug_break() __debugbreak();