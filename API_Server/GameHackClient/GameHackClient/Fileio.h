#ifndef FILE_IO_H
#define FILE_IO_H

#include <windows.h>
#include <string>
#include <ctime>
#include <fstream>
#include <sstream>
#include <iostream>
#include <optional>

std::optional <std::string> FileCreater(std::string filename, PUCHAR BUFFER, SIZE_T BUFFER_SIZE); //颇老 积己
bool DeleteFileIfExists(const std::string& path); // 颇老 昏力 
#endif