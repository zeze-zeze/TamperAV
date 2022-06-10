#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>

BOOL dllInject();
std::uint32_t get_proc_id(const std::wstring& name);
BOOL ObtainSeDebugPrivilege();