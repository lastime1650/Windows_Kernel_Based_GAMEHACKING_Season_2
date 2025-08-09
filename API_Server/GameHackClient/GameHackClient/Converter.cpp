#include "Converter.h"


// PUCHAR -> String ( 0xABC )
std::optional<std::string> Pointer_to_String(PUCHAR address) {
    if (!address) {
        return std::nullopt;
    }

    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << reinterpret_cast<std::uintptr_t>(address);
    return oss.str();
}