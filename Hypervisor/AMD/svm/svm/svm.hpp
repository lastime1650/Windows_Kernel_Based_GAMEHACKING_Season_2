#pragma once
#include "def/cpu.hpp"
#include "def/descriptors-info.hpp"
#include "def/vmexit.hpp"
#include "def/virtual-memory.hpp"
#include "def/vmcb.hpp"
#include "def/vprocessor-data.hpp"
#include "../common-includes.hpp"
#include "util/util.hpp"
#include "handlers/handlers.hpp"
#pragma warning (disable : 4245)
#pragma warning (disable : 4390)

namespace svm
{
	__declspec(noreturn) extern "C" void __stdcall vmenter(PVOID host_rsp);

	bool check_support();

	void virtualize(PVOID);

	void devirtualize();
}