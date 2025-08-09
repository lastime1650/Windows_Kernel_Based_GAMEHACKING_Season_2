#include "IOCTL_Manager.h"
#include "base64.h"
#include "Fileio.h"



IOCTL_Manager::IOCTL_Manager() {

	MyPID = GetCurrentProcessId();
	
	IOCTL_Handle = CreateFileW(
		SYMBOLIC_NAME,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	IsConnect = IsConnected();


	// NamedPipe 실행 (지속수신)
	if (IsConnect) {
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&Do_PIPE, NULL, 0, NULL);
	}

}
IOCTL_Manager::~IOCTL_Manager() {
	if (IsConnect) {
		CloseHandle(IOCTL_Handle);
		IOCTL_Handle = NULL;
	}
}


BOOLEAN IOCTL_Manager::IsConnected() {
	if (IOCTL_Handle == INVALID_HANDLE_VALUE || IOCTL_Handle == NULL)
		return FALSE;
	else 
		return TRUE;
}

////
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <iostream>
///
#include "Converter.h"

typedef enum scantype {
	Int32 = 0,
	UInt32,
	Int64,
	UInt64, 
	Float, // 0x000...
	Double, // 0x000...
	Address // 0xABC...

}scantype;

std::string IOCTL_Manager::NewScanning(rapidjson::Document& JSON) {
	/*
		요청 JSON 구조
		{
			"cmd" ... 호출자에서 부담.

			"target_processid": int, // 타겟 프로세스 ID
			"type": enum(int)
			"value": string


		}
		--
		
		반환 JSON 구조
		{
			"status" : true 또는 false,
			"addresses" : [
				" 0x00.....",
				" 0x00....",,,,,,,,
			]
		}
	
	*/
	if (!JSON.HasMember("target_processid") || !JSON.HasMember("type") || !JSON.HasMember("value"))
		return std::string( "WRONG KEY");

	DWORD Target_ProcessId = static_cast<DWORD>( JSON["target_processid"].GetUint() );
	scantype ScanType = static_cast<scantype>( JSON["type"].GetUint() );
	std::string value_str = static_cast<std::string>( JSON["value"].GetString() );

	PUCHAR value_data_ = NULL;
	SIZE_T value_data_size_ = 0;
	switch (ScanType) {

	case Int32: {
		int32_t value = std::stoi(value_str);
		value_data_size_ = sizeof(int32_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case UInt32: {
		uint32_t value = static_cast<uint32_t>(std::stoul(value_str));
		value_data_size_ = sizeof(uint32_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case Int64: {
		int64_t value = std::stoll(value_str);
		value_data_size_ = sizeof(int64_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case UInt64: {
		uint64_t value = std::stoull(value_str);
		value_data_size_ = sizeof(uint64_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case Float: {
		float value = std::stof(value_str);
		value_data_size_ = sizeof(float);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case Double: {
		double value = std::stod(value_str);
		value_data_size_ = sizeof(double);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case Address: {
		uint64_t value = std::stoull(value_str, nullptr, 16);  // 16진수 해석
		value_data_size_ = sizeof(uint64_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	default:
		return std::string("NOT SUPPORT TYPE");
	}

	if (!value_data_ || !value_data_size_)
		return std::string("FAILED value_data_");

	// Call 2 Kernel
	PScanNode output = newscan(
									(HANDLE)Target_ProcessId,
									value_data_,
									value_data_size_
								);


	// To JSON for Result to WS Client
	rapidjson::Document OutputJSON;
	OutputJSON.SetObject();
	auto& allocator = OutputJSON.GetAllocator();

	

	if (output) {
		// Add "status"
		OutputJSON.AddMember(
			"status",
			true,
			allocator
		);

		rapidjson::Value arr(rapidjson::kArrayType); // 배열
		PScanNode current_output = output;
		while (current_output) {
			
			std::optional<std::string> addr2str = Pointer_to_String(current_output->Detected_Address);
			if (addr2str) {
				arr.PushBack(
					rapidjson::Value().SetString(addr2str->c_str(), allocator),
					allocator
				);
			}

			

			PScanNode previous_node = current_output;

			current_output = (PScanNode)current_output->NextNode;

			VirtualFree(previous_node, 0, MEM_RELEASE);
		}

		// Add "addresses"
		OutputJSON.AddMember(
			"addresses",
			arr,
			allocator
		);

		

	}
	else {
		// Add "status"
		OutputJSON.AddMember(
			"status",
			false,
			allocator
		);
	}

	// JSON 문자열 출력
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	OutputJSON.Accept(writer);

	free(value_data_);

	return std::string(buffer.GetString());
}



PScanNode IOCTL_Manager::newscan(HANDLE Target_ProcessId, PUCHAR value_data, SIZE_T value_size) {

	NewScan INPUT = { 0, };
	INPUT.RequesterPID = (HANDLE)MyPID;
	INPUT.TargetPID = Target_ProcessId;
	INPUT.value = value_data;
	INPUT.value_size = value_size;
	INPUT.Output = NULL;

	NewScan OUTPUT = { 0, };

	BOOL result = call_to_kernel(
		IOCTL_Handle,
		IOCTL_NEWSCAN,

		&INPUT,
		sizeof(INPUT),
		&OUTPUT,
		sizeof(OUTPUT)
	);

	return OUTPUT.Output;
}


std::string IOCTL_Manager::AddressScanning(rapidjson::Document& JSON) {
	/*
		요청 JSON 구조
		{
			"cmd" ... 호출자에서 부담.

			"target_processid": int, // 타겟 프로세스 ID

			"target_address": string

			"type": enum(int)
			"value": string


		}
		--

		반환 JSON 구조
		{
			"status" : true 또는 false,
			"is_same": 조사할 값과 현재 메모리에 저장된 값이 같은가?
			"current_value": 메모리에 저장된 값 ( base64 ) 
			"current_value_size": uint64
		}

	*/
	if (!JSON.HasMember("target_processid") || !JSON.HasMember("type") || !JSON.HasMember("value") || !JSON.HasMember("target_address"))
		return std::string("WRONG KEY");

	DWORD Target_ProcessId = static_cast<DWORD>(JSON["target_processid"].GetUint());
	scantype ScanType = static_cast<scantype>(JSON["type"].GetUint());
	std::string value_str = static_cast<std::string>(JSON["value"].GetString());
	std::string Target_Address_str = static_cast<std::string>(JSON["target_address"].GetString());

	uint64_t Target_Address_int64 = std::stoull(Target_Address_str, nullptr, 16);
	PUCHAR Target_Address = reinterpret_cast<PUCHAR>(Target_Address_int64);

	PUCHAR value_data_ = NULL;
	SIZE_T value_data_size_ = 0;
	switch (ScanType) {

	case Int32: {
		int32_t value = std::stoi(value_str);
		value_data_size_ = sizeof(int32_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case UInt32: {
		uint32_t value = static_cast<uint32_t>(std::stoul(value_str));
		value_data_size_ = sizeof(uint32_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case Int64: {
		int64_t value = std::stoll(value_str);
		value_data_size_ = sizeof(int64_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case UInt64: {
		uint64_t value = std::stoull(value_str);
		value_data_size_ = sizeof(uint64_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case Float: {
		float value = std::stof(value_str);
		value_data_size_ = sizeof(float);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case Double: {
		double value = std::stod(value_str);
		value_data_size_ = sizeof(double);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case Address: {
		uint64_t value = std::stoull(value_str, nullptr, 16);  // 16진수 해석
		value_data_size_ = sizeof(uint64_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	default:
		return std::string("NOT SUPPORT TYPE");
	}

	if (!value_data_ || !value_data_size_)
		return std::string("FAILED value_data_");

	PAddressScanned output = addressscan(
		(HANDLE)Target_ProcessId,
		Target_Address,
		value_data_,
		value_data_size_
	);

	// To JSON for Result to WS Client
	rapidjson::Document OutputJSON;
	OutputJSON.SetObject();
	auto& allocator = OutputJSON.GetAllocator();

	if (output) {
		// Add "status"
		OutputJSON.AddMember(
			"status",
			true,
			allocator
		);

		OutputJSON.AddMember(
			"is_same",
			output->is_same,
			allocator
		);

		// base64 encode
		OutputJSON.AddMember(
			"current_value",
			rapidjson::Value().SetString( base64_encode(output->current_value, output->current_value_size).c_str(), allocator),
			allocator
		);
		
		OutputJSON.AddMember(
			"current_value_size",
			rapidjson::Value().SetUint64(output->current_value_size),
			allocator
		);


		if (output->current_value)
			VirtualFree(
				output->current_value,
				0,
				MEM_RELEASE
			);
		
		VirtualFree(
			output,
			0,
			MEM_RELEASE
		);
	}
	else {
		// Add "status"
		OutputJSON.AddMember(
			"status",
			false,
			allocator
		);
	}

	// JSON 문자열 출력
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	OutputJSON.Accept(writer);

	free(value_data_);

	return std::string(buffer.GetString());

}

PAddressScanned IOCTL_Manager::addressscan(HANDLE Target_ProcessId, PUCHAR TargetAddress, PUCHAR value_data, SIZE_T value_size) {
	AddressScan INPUT = { 0, };
	INPUT.RequesterPID = (HANDLE)MyPID;
	INPUT.TargetPID = Target_ProcessId;
	INPUT.TargetAddress = TargetAddress;
	INPUT.value = value_data;
	INPUT.value_size = value_size;
	INPUT.Output = NULL;

	AddressScan OUTPUT = { 0, };

	BOOL result = call_to_kernel(
		IOCTL_Handle,
		IOCTL_TARGETSCAN,

		&INPUT,
		sizeof(INPUT),
		&OUTPUT,
		sizeof(OUTPUT)
	);

	return OUTPUT.Output;
}

std::string IOCTL_Manager::MemDumping(rapidjson::Document& JSON){
	/*
		요청 JSON 구조
		{
			"cmd" ... 호출자에서 부담.

			"target_processid": int, // 타겟 프로세스 ID

			"target_address": string

			"dump_size": int


		}
		--

		반환 JSON 구조
		{
			"status" : true 또는 false,
			"dumped" : {
				data: base64
				data_size: int
				protect: int
				state: int
			}
		}

	*/
	if (!JSON.HasMember("target_processid") || !JSON.HasMember("dump_size") || !JSON.HasMember("target_address"))
		return std::string("WRONG KEY");

	DWORD Target_ProcessId = static_cast<DWORD>(JSON["target_processid"].GetUint());

	std::string Target_Address_str = static_cast<std::string>(JSON["target_address"].GetString());
	uint64_t Target_Address_int64 = std::stoull(Target_Address_str, nullptr, 16);
	PUCHAR Target_Address = reinterpret_cast<PUCHAR>(Target_Address_int64);

	SIZE_T DumpSize = static_cast<SIZE_T>( JSON["dump_size"].GetUint64() );

	PMemDumpOutput output = memdump(
		(HANDLE)Target_ProcessId,
		Target_Address,
		DumpSize
	);

	// To JSON for Result to WS Client
	rapidjson::Document OutputJSON;
	OutputJSON.SetObject();
	auto& allocator = OutputJSON.GetAllocator();

	if (output) {
		// Add "status"
		OutputJSON.AddMember(
			"status",
			true,
			allocator
		);

		
		/*
			지정한 메모리 주소와 길이 지정
		*/
		if (output->Dumped_StartAddress) {
			std::string Dump = base64_encode(output->Dumped_StartAddress, DumpSize);
			if (!Dump.empty()) {
				OutputJSON.AddMember(
					"dump_data",
					rapidjson::Value().SetString(Dump.c_str(), allocator),
					allocator
				);
				OutputJSON.AddMember(
					"dump_data_size",
					rapidjson::Value().SetUint64(DumpSize),
					allocator
				);
			}
			VirtualFree(output->Dumped_StartAddress, 0, MEM_RELEASE);
		}
		

		/*
			PAGE 영역 전체
		*/
		if (output->Dumped_PAGE_BasedAddress) {
			std::string PageDump = base64_encode(output->Dumped_PAGE_BasedAddress, output->PAGE_Size);
			if (!PageDump.empty()) {
				OutputJSON.AddMember(
					"page_dump_data",
					rapidjson::Value().SetString(PageDump.c_str(), allocator),
					allocator
				);
				OutputJSON.AddMember(
					"page_dump_data_size",
					rapidjson::Value().SetUint64(output->PAGE_Size),
					allocator
				);
			}
			VirtualFree(output->Dumped_PAGE_BasedAddress, 0, MEM_RELEASE);
		}
		
		std::optional<std::string> addr2str = Pointer_to_String(output->PAGE_BaseAddress);
		if(addr2str)
			OutputJSON.AddMember(
				"page_baseaddress",
				rapidjson::Value().SetString(addr2str.value().c_str(), allocator),
				allocator
			);

		OutputJSON.AddMember(
			"protect",
			rapidjson::Value().SetUint(output->PAGE_Protect),
			allocator
		);
		OutputJSON.AddMember(
			"state",
			rapidjson::Value().SetUint(output->PAGE_State),
			allocator
		);

		if (output)
			VirtualFree(output, 0, MEM_RELEASE);
	}
	else {
		// Add "status"
		OutputJSON.AddMember(
			"status",
			false,
			allocator
		);
	}

	// JSON 문자열 출력
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	OutputJSON.Accept(writer);

	
	return std::string(buffer.GetString());
}
PMemDumpOutput IOCTL_Manager::memdump(HANDLE Target_ProcessId, PUCHAR TargetAddress, SIZE_T dump_size){

	MemDump INPUT = { 0, };
	INPUT.RequesterPID = (HANDLE)GetCurrentProcessId();
	INPUT.TargetPID = Target_ProcessId;
	INPUT.StartAddress = TargetAddress;
	INPUT.Size = dump_size;
	INPUT.Output = NULL;

	MemDump OUTPUT = { 0, };

	call_to_kernel(
		IOCTL_Handle,
		IOCTL_MEMDUMP,
		&INPUT,
		sizeof(INPUT),
		&OUTPUT,
		sizeof(OUTPUT)
	);

	return OUTPUT.Output;
}


std::string IOCTL_Manager::DLL_Injection(rapidjson::Document& JSON) {
	/*
		요청 JSON 구조
		{
			"cmd" ... 호출자에서 부담.

			"target_processid": int, // 타겟 프로세스 ID

			"dll_name": string

			"dll_data": string( base64 )

			"dll_size": uint64


		}
		--

		반환 JSON 구조
		{
			"status" : true 또는 false,
		}

	*/
	if (!JSON.HasMember("target_processid") || !JSON.HasMember("dll_name") || !JSON.HasMember("dll_data") || !JSON.HasMember("dll_size"))
		return std::string("WRONG KEY");

	DWORD Target_ProcessId = static_cast<DWORD>(JSON["target_processid"].GetUint());
	std::string dll_name = JSON["dll_name"].GetString();
	std::string dll_data = JSON["dll_data"].GetString(); // base64
	uint64_t dll_size = JSON["dll_size"].GetUint64();

	// decode
	PUCHAR DLL_DATA_BUFFER = (PUCHAR)malloc(dll_size);
	std::string decoded = base64_decode(dll_data);
	memcpy(DLL_DATA_BUFFER, decoded.c_str(), decoded.size());


	NTSTATUS status = dll_injection(
		(HANDLE)Target_ProcessId,
		dll_name.c_str(),
		DLL_DATA_BUFFER,
		dll_size
	);

	// To JSON for Result to WS Client
	rapidjson::Document OutputJSON;
	OutputJSON.SetObject();
	auto& allocator = OutputJSON.GetAllocator();

	if (status == CMC_STATUS_SUCCESS) {
		// Add "status"
		OutputJSON.AddMember(
			"status",
			true,
			allocator
		);
	}
	else {
		// Add "status"
		OutputJSON.AddMember(
			"status",
			false,
			allocator
		);
	}

	// JSON 문자열 출력
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	OutputJSON.Accept(writer);


	return std::string(buffer.GetString());
}

NTSTATUS IOCTL_Manager::dll_injection(HANDLE Target_ProcessId, const char* DLL_NAME, PUCHAR DLL_BUFFER, SIZE_T DLL_BUFFER_SIZE) {


	std::optional <std::string> filename = FileCreater(DLL_NAME, DLL_BUFFER, DLL_BUFFER_SIZE);
	if (!filename)
		return STATUS_DLL_NOT_FOUND; // ? 


	DLL_INJECTION_INPUT INPUT = { 0, };
	INPUT.ProcessId = Target_ProcessId;
	memcpy(INPUT.Injection_Dll_PATH, filename.value().c_str(), filename.value().size());
	INPUT.Output = NULL;

	DLL_INJECTION_INPUT OUTPUT = { 0, };

	call_to_kernel(
		IOCTL_Handle,
		IOCTL_DLLINJECTION,
		&INPUT,
		sizeof(INPUT),
		&OUTPUT,
		sizeof(OUTPUT)
	);
	//DeleteFileIfExists()....
	return OUTPUT.Output;
}

std::string IOCTL_Manager::MemWriting(rapidjson::Document& JSON) {
	/*
		요청 JSON 구조
		{
			"cmd" ... 호출자에서 부담.

			"target_processid": int, // 타겟 프로세스 ID

			"target_address": string

			"type": enum(int)
			"value": string

			"is_force"


		}
		--

		반환 JSON 구조
		{
			"status" : true 또는 false,
		}

	*/
	if (!JSON.HasMember("target_processid") || !JSON.HasMember("target_address") || !JSON.HasMember("is_force") || !JSON.HasMember("type") || !JSON.HasMember("value"))
		return std::string("WRONG KEY");

	DWORD Target_ProcessId = static_cast<DWORD>(JSON["target_processid"].GetUint());
	scantype ScanType = static_cast<scantype>(JSON["type"].GetUint());
	std::string value_str = static_cast<std::string>(JSON["value"].GetString());
	std::string Target_Address_str = static_cast<std::string>(JSON["target_address"].GetString());
	uint64_t Target_Address_int64 = std::stoull(Target_Address_str, nullptr, 16);
	PUCHAR Target_Address = reinterpret_cast<PUCHAR>(Target_Address_int64);
	BOOLEAN is_force = JSON["is_force"].GetBool();

	PUCHAR value_data_ = NULL;
	SIZE_T value_data_size_ = 0;
	switch (ScanType) {

	case Int32: {
		int32_t value = std::stoi(value_str);
		value_data_size_ = sizeof(int32_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case UInt32: {
		uint32_t value = static_cast<uint32_t>(std::stoul(value_str));
		value_data_size_ = sizeof(uint32_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case Int64: {
		int64_t value = std::stoll(value_str);
		value_data_size_ = sizeof(int64_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case UInt64: {
		uint64_t value = std::stoull(value_str);
		value_data_size_ = sizeof(uint64_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case Float: {
		float value = std::stof(value_str);
		value_data_size_ = sizeof(float);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case Double: {
		double value = std::stod(value_str);
		value_data_size_ = sizeof(double);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	case Address: {
		uint64_t value = std::stoull(value_str, nullptr, 16);  // 16진수 해석
		value_data_size_ = sizeof(uint64_t);
		value_data_ = (PUCHAR)malloc(value_data_size_);
		memcpy(value_data_, &value, value_data_size_);
		break;
	}

	default:
		return std::string("NOT SUPPORT TYPE");
	}

	if (!value_data_ || !value_data_size_)
		return std::string("FAILED value_data_");
	// To JSON for Result to WS Client
	rapidjson::Document OutputJSON;
	OutputJSON.SetObject();
	auto& allocator = OutputJSON.GetAllocator();

	PUCHAR output = memwrite(
		(HANDLE)Target_ProcessId,
		Target_Address,
		value_data_,
		value_data_size_,
		is_force
	);

	if (output) {
		// Add "status"
		OutputJSON.AddMember(
			"status",
			true,
			allocator
		);
	}
	else {
		// Add "status"
		OutputJSON.AddMember(
			"status",
			false,
			allocator
		);
	}

	// JSON 문자열 출력
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	OutputJSON.Accept(writer);

	free(value_data_);

	return std::string(buffer.GetString());
}
PUCHAR IOCTL_Manager::memwrite(HANDLE Target_ProcessId, PUCHAR TargetAddress, PUCHAR value_data, SIZE_T value_size, BOOLEAN is_Protect_Change_Enable) {
	MemWrite INPUT = { 0, };
	INPUT.RequesterPID = (HANDLE)GetCurrentProcessId();
	INPUT.TargetPID = Target_ProcessId;
	INPUT.TargetAddress = TargetAddress;
	INPUT.value = value_data;
	INPUT.value_size = value_size;
	INPUT.is_Protect_Change_Enable = is_Protect_Change_Enable;
	INPUT.Output = NULL;

	MemWrite OUTPUT = { 0, };

	call_to_kernel(
		IOCTL_Handle,
		IOCTL_MEMWRITE,
		&INPUT,
		sizeof(INPUT),
		&OUTPUT,
		sizeof(OUTPUT)
	);
	return OUTPUT.Output;
}

std::string IOCTL_Manager::Set_HW_BP(rapidjson::Document& JSON) {
	/*
		요청 JSON 구조
		{
			"cmd" ... 호출자에서 부담.

			"target_processid": int, // 타겟 프로세스 ID

			"target_address": string

			"is_remove": boolean

		}
		--

		반환 JSON 구조
		{
			"status" : true 또는 false,
		}

	*/
	if (!JSON.HasMember("target_processid") || !JSON.HasMember("target_address") || !JSON.HasMember("is_remove"))
		return std::string("WRONG KEY");

	DWORD Target_ProcessId = static_cast<DWORD>(JSON["target_processid"].GetUint());
	BOOLEAN is_Remove = JSON["is_remove"].GetBool() ;
	std::string Target_Address_str = static_cast<std::string>(JSON["target_address"].GetString());
	uint64_t Target_Address_int64 = std::stoull(Target_Address_str, nullptr, 16);
	PUCHAR Target_Address = reinterpret_cast<PUCHAR>(Target_Address_int64);
	
	NTSTATUS status = set_HardwareBP(
		(HANDLE)Target_ProcessId,
		Target_Address,
		is_Remove
	);


	// To JSON for Result to WS Client
	rapidjson::Document OutputJSON;
	OutputJSON.SetObject();
	auto& allocator = OutputJSON.GetAllocator();

	if (status == CMC_STATUS_SUCCESS) {
		// Add "status"
		OutputJSON.AddMember(
			"status",
			true,
			allocator
		);
	}
	else {
		// Add "status"
		OutputJSON.AddMember(
			"status",
			false,
			allocator
		);
	}

	// JSON 문자열 출력
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	OutputJSON.Accept(writer);

	return std::string(buffer.GetString());
}

NTSTATUS IOCTL_Manager::set_HardwareBP(HANDLE Target_ProcessId, PUCHAR TargetAddress, BOOLEAN is_remove) {
	Hardware_Breakpoint INPUT = { 0, };
	INPUT.TargetPID = Target_ProcessId;
	INPUT.TargetAddress = TargetAddress;
	INPUT.Output = NULL;

	Hardware_Breakpoint OUTPUT = { 0, };

	call_to_kernel(
		IOCTL_Handle,
		IOCTL_HardwareBP,
		&INPUT,
		sizeof(INPUT),
		&OUTPUT,
		sizeof(OUTPUT)
	);
	return OUTPUT.Output;
}


std::string IOCTL_Manager::MemAllScanning(rapidjson::Document& JSON) {
	/*
		요청 JSON 구조
		{
			"cmd" ... 호출자에서 부담.

			"target_processid": int, // 타겟 프로세스 ID

			"type": uint

		}
		--

		반환 JSON 구조
		{
			"status" : true 또는 false,
		}

	*/
	if (!JSON.HasMember("target_processid") || !JSON.HasMember("type"))
		return std::string("WRONG KEY");

	DWORD Target_ProcessId = static_cast<DWORD>(JSON["target_processid"].GetUint());
	scantype ScanType = static_cast<scantype>(JSON["type"].GetUint());

	SIZE_T value_data_size_ = 0;
	switch (ScanType) {

	case Int32: {
		value_data_size_ = sizeof(int32_t);
		break;
	}

	case UInt32: {
		value_data_size_ = sizeof(uint32_t);
		break;
	}

	case Int64: {
		value_data_size_ = sizeof(int64_t);
		break;
	}

	case UInt64: {
		value_data_size_ = sizeof(uint64_t);
		break;
	}

	case Float: {
		value_data_size_ = sizeof(float);
		break;
	}

	case Double: {
		value_data_size_ = sizeof(double);
		break;
	}

	case Address: {
		value_data_size_ = sizeof(uint64_t);
		break;
	}

	default:
		return std::string("NOT SUPPORT TYPE");
	}

	if (!value_data_size_)
		return std::string("FAILED value_data_");

	// To JSON for Result to WS Client
	rapidjson::Document OutputJSON;
	OutputJSON.SetObject();
	auto& allocator = OutputJSON.GetAllocator();

	PAllScannedNode output = allscan( (HANDLE)Target_ProcessId, value_data_size_);

	if (output) {
		// Add "status"
		OutputJSON.AddMember(
			"status",
			true,
			allocator
		);

		rapidjson::Value arr(rapidjson::kArrayType); // 배열
		PAllScannedNode current_output = output;
		while (current_output) {

			rapidjson::Value scanned_node(rapidjson::kObjectType); // { "value": .. , "target_address": ... }


			std::string value_enc = base64_encode((PUCHAR)current_output->value, value_data_size_);
			if (!value_enc.empty()) {

				scanned_node.AddMember("value", rapidjson::Value().SetString(value_enc.c_str(), allocator), allocator); // "value" - KEY - string
				scanned_node.AddMember(																					// "target_address" - KEY - string
					"target_address", 
					rapidjson::Value().SetString( 

						Pointer_to_String(
							current_output->Target_Address
						).value().c_str(), 

						allocator
					), 
					allocator
				);


				arr.PushBack(
					scanned_node,
					allocator
				); // append {} -( to )-> [] array
			}

			VirtualFree(current_output->value, 0, MEM_RELEASE);

			PAllScannedNode previous_node = current_output;

			current_output = (PAllScannedNode)current_output->NextNode;

			VirtualFree(previous_node, 0, MEM_RELEASE);
		}

		// Add "scanned"
		OutputJSON.AddMember( // "scanned" : array[ JSON{}, JSON{},,, ]
			"scanned",
			arr,
			allocator
		);



	}
	else {
		// Add "status"
		OutputJSON.AddMember(
			"status",
			false,
			allocator
		);
	}

	// JSON 문자열 출력
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	OutputJSON.Accept(writer);

	return std::string(buffer.GetString());

}
PAllScannedNode IOCTL_Manager::allscan(HANDLE Target_ProcessId, SIZE_T value_size) {

	AllScan INPUT = { 0, };
	INPUT.RequesterPID = (HANDLE)GetCurrentProcessId();
	INPUT.TargetPID = Target_ProcessId;
	INPUT.value_size = value_size;
	INPUT.Output = NULL;

	AllScan OUTPUT = { 0, };

	call_to_kernel(
		IOCTL_Handle,
		IOCTL_MEMALLSCAN,
		&INPUT,
		sizeof(INPUT),
		&OUTPUT,
		sizeof(OUTPUT)
	);
	return OUTPUT.Output;
}

BOOL IOCTL_Manager::call_to_kernel(
	HANDLE ioctl_handle,
	DWORD ioctl_code,

	PVOID INPUT,
	DWORD INPUT_SIZE,

	PVOID OUTPUT,
	DWORD OUTPUT_SIZE
) {
	DWORD returnBytes = 0;
	return DeviceIoControl(
		IOCTL_Handle,
		ioctl_code,
		INPUT,
		INPUT_SIZE,
		OUTPUT,
		OUTPUT_SIZE,
		&returnBytes,
		NULL
	);
}

