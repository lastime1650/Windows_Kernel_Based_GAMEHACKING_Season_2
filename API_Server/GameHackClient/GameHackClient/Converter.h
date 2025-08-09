#ifndef CONVERTER_H
#define CONVERTER_H

#include <Windows.h>
#include <iostream>
#include <string>
#include <optional>
#include <sstream>  // ¶Ç´Â <cstdio>
#include <iomanip>  // std::hex
#include <cstdint>  // uintptr_t

// PUCHAR -> String ( 0xABC )
std::optional<std::string> Pointer_to_String(PUCHAR address);



#endif // !CONVERTER_H
