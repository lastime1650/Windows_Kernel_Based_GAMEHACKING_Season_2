#include "Fileio.h"

std::optional <std::string> FileCreater(std::string filename, PUCHAR BUFFER, SIZE_T BUFFER_SIZE) {

	// 유닉스 타임스탬프 얻기
	std::time_t unixTimestamp = std::time(nullptr);

	// 파일 이름 만들기 : baseName_timestamp.dll
	std::ostringstream filenameStream;
	filenameStream << "C:\\" << filename << "_" << unixTimestamp << ".dll";
	std::string Generated__filename = filenameStream.str();

	// 파일 생성 및 쓰기 (바이너리 모드)
	std::ofstream outFile(Generated__filename, std::ios::out | std::ios::binary);
	if (!outFile) {
		std::cerr << "파일 생성 실패: " << Generated__filename << std::endl;
		return std::nullopt;
	}

	outFile.write(reinterpret_cast<const char*>(BUFFER), BUFFER_SIZE);
	outFile.close();

	return Generated__filename;
}

#include <filesystem>
bool DeleteFileIfExists(const std::string& path) {
	try {
		return std::filesystem::remove(path);  // 삭제 성공 시 true
	}
	catch (const std::filesystem::filesystem_error& e) {
		std::cerr << "파일 삭제 실패: " << e.what() << std::endl;
		return false;
	}
}