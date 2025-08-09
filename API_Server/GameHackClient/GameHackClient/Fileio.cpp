#include "Fileio.h"

std::optional <std::string> FileCreater(std::string filename, PUCHAR BUFFER, SIZE_T BUFFER_SIZE) {

	// ���н� Ÿ�ӽ����� ���
	std::time_t unixTimestamp = std::time(nullptr);

	// ���� �̸� ����� : baseName_timestamp.dll
	std::ostringstream filenameStream;
	filenameStream << "C:\\" << filename << "_" << unixTimestamp << ".dll";
	std::string Generated__filename = filenameStream.str();

	// ���� ���� �� ���� (���̳ʸ� ���)
	std::ofstream outFile(Generated__filename, std::ios::out | std::ios::binary);
	if (!outFile) {
		std::cerr << "���� ���� ����: " << Generated__filename << std::endl;
		return std::nullopt;
	}

	outFile.write(reinterpret_cast<const char*>(BUFFER), BUFFER_SIZE);
	outFile.close();

	return Generated__filename;
}

#include <filesystem>
bool DeleteFileIfExists(const std::string& path) {
	try {
		return std::filesystem::remove(path);  // ���� ���� �� true
	}
	catch (const std::filesystem::filesystem_error& e) {
		std::cerr << "���� ���� ����: " << e.what() << std::endl;
		return false;
	}
}