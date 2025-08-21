#pragma warning(disable:4996)
#include "PE_logic.h"
#include "API.h"

NTSTATUS Dll_API_Address_Search(
	HANDLE Processid,

	PWCH Dll_Name, // Dll Name
	PCHAR Api_Name, // API Name

	PUCHAR* Dll_Base_VirtualAddress, // Dll Base Address
	PUCHAR* API_VirtualAddress
) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (
		!Dll_Name ||
		!Api_Name ||
		!API_VirtualAddress || 
		!Dll_Base_VirtualAddress) {
		return STATUS_INVALID_PARAMETER;
	}

	/*
	==================================================================
	Find DLL ! From TargetProcess

	** Attention
	* should be know the target process 32 or 64 bit !!!  ( for PE parsing )
	* If return the API Address, it is a VIrtual Address! Not Kernel Address... !!!@@#$!@
	
	STEP 1) Looking for the Eprocess from PID

	STEP 2) Attach to UserMode target process Context

	STEP 3) Get PEB

	STEP 4) Get Dll informations from LDR ..

	STEP 5) Get Api Address from Dll Base Address

	==================================================================
	*/

	

	// STEP 1
	PEPROCESS targetProcess = NULL;
	status = PsLookupProcessByProcessId(Processid, &targetProcess);
	if (!NT_SUCCESS(status))
		goto EXIT0;

	// STEP 2
	KAPC_STATE APC_STATE;
	KeStackAttachProcess(targetProcess, &APC_STATE);

	// STEP 3
	PPEB Peb = PsGetProcessPeb(targetProcess);
	if (!Peb) {
		status = STATUS_UNSUCCESSFUL;
		goto EXIT2;
	}

	// find the dll
	if (Peb->Ldr && Peb->Ldr->InMemoryOrderModuleList.Flink) {
	
		PLIST_ENTRY ListHead = &Peb->Ldr->InMemoryOrderModuleList;
		PLIST_ENTRY CurrentEntry = ListHead->Flink;

		UNICODE_STRING moduleName;
		RtlInitUnicodeString(&moduleName, Dll_Name);

		// STEP 4
		while (CurrentEntry != ListHead) {
		
			PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			// Compare the Dll Name
			if (RtlEqualUnicodeString(&LdrEntry->BaseDllName, &moduleName, TRUE)) {
				// Found the Dll
				*Dll_Base_VirtualAddress = LdrEntry->DllBase; // Set Dll Base Address

				// STEP 5
				PIMAGE_DOS_HEADER__ DllDosHeader = (PIMAGE_DOS_HEADER__)LdrEntry->DllBase;
				if (DllDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
					DbgPrintEx(
						DPFLTR_IHVDRIVER_ID,
						DPFLTR_ERROR_LEVEL,
						" Invalid Dll Dos Header Signature %d \n", Processid
					);
					status = STATUS_INVALID_IMAGE_FORMAT;
					goto EXIT2;
				}

				PIMAGE_EXPORT_DIRECTORY ExportDir = NULL;

				BOOLEAN is64bit = (PsGetProcessWow64Process(targetProcess) == NULL); // if NULL, its 64bit process
				if (is64bit) {
					
					
					
					// 64bit
					PIMAGE_NT_HEADERS64__ NtHeaders64 = (PIMAGE_NT_HEADERS64__)((PUCHAR)LdrEntry->DllBase + DllDosHeader->e_lfanew);

					if (
						NtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
					) {
						ExportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)LdrEntry->DllBase + NtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

					}

				}
				else {
					// 32bit
					PIMAGE_NT_HEADERS32__ NtHeaders32 = (PIMAGE_NT_HEADERS32__)((PUCHAR)LdrEntry->DllBase + DllDosHeader->e_lfanew);

					if (
						NtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
					) {
						ExportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)LdrEntry->DllBase + NtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
					}

				}

				if (!ExportDir) {
					DbgPrintEx(
						DPFLTR_IHVDRIVER_ID,
						DPFLTR_ERROR_LEVEL,
						" No Export APIS \n"
					);
					status = STATUS_NOT_FOUND;
					goto EXIT2;
				}

				PULONG pAddressOfFunctions = (PULONG)((PUCHAR)LdrEntry->DllBase + ExportDir->AddressOfFunctions);
				PULONG pAddressOfNames = (PULONG)((PUCHAR)LdrEntry->DllBase + ExportDir->AddressOfNames);
				PUSHORT  pAddressOfNameOrdinals = (PUSHORT)((PUCHAR)LdrEntry->DllBase + ExportDir->AddressOfNameOrdinals);

				// 2. Export된 모든 함수 이름을 순회합니다.
				for (ULONG i = 0; i < ExportDir->NumberOfNames; i++) {

					PUCHAR Functionname = ( (PUCHAR)LdrEntry->DllBase + pAddressOfNames[i]);

					USHORT Oridnal = pAddressOfNameOrdinals[i];

					ULONG FunctionRva = pAddressOfFunctions[Oridnal];

					PUCHAR FunctionAddress = ( (PUCHAR)LdrEntry->DllBase + FunctionRva);

					// Compare API Name
					if (strcmp((PCHAR)Functionname, Api_Name) != 0) {
						continue; // Skip if not match
					}

					// Found the API

					DbgPrintEx(
						DPFLTR_IHVDRIVER_ID,
						DPFLTR_ERROR_LEVEL,
						"성공: API '%s'를 찾았습니다. 주소: %p \n",
						Functionname,
						FunctionAddress
					);

					*API_VirtualAddress = FunctionAddress;

					goto EXIT2;
				}

				break;
			}

			CurrentEntry = CurrentEntry->Flink; // Move to next entry


		}


	}
	else {
		DbgPrintEx(
			DPFLTR_IHVDRIVER_ID,
			DPFLTR_ERROR_LEVEL,
			" Can't found LDR from PEB %d \n", Processid
		);
	}


	
	
EXIT2:
	KeUnstackDetachProcess(&APC_STATE);
	ObDereferenceObject(targetProcess);
EXIT0:
	return status;
}


NTSTATUS Get_ImageInformation_by_ProcessId(HANDLE ProcessId, PImageInformation* output) {
	
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	// STEP 1
	PEPROCESS targetProcess = NULL;
	status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
	if (!NT_SUCCESS(status))
		goto EXIT0;

	// STEP 2
	KAPC_STATE APC_STATE;
	KeStackAttachProcess(targetProcess, &APC_STATE);

	// STEP 3
	PPEB Peb = PsGetProcessPeb(targetProcess);
	if (!Peb) {
		status = STATUS_UNSUCCESSFUL;
		goto EXIT1;
	}


	PImageInformation StartNode = NULL;
	PImageInformation CurrentNode = NULL;

	// find the dll
	if (Peb->Ldr && Peb->Ldr->InMemoryOrderModuleList.Flink) {




		PLIST_ENTRY ListHead = &Peb->Ldr->InMemoryOrderModuleList;
		PLIST_ENTRY CurrentEntry = ListHead->Flink;


		// STEP 4
		while (CurrentEntry != ListHead) {

			PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			/*
			
			
			
			*/
			// STEP 5
			PIMAGE_DOS_HEADER__ DllDosHeader = (PIMAGE_DOS_HEADER__)LdrEntry->DllBase;
			PIMAGE_NT_HEADERS64__ NtHeaders64 = (PIMAGE_NT_HEADERS64__)((PUCHAR)LdrEntry->DllBase + DllDosHeader->e_lfanew);

			PIMAGE_SECTION_HEADER__ SectionHeader = (PIMAGE_SECTION_HEADER__)( (PUCHAR)&NtHeaders64->OptionalHeader + NtHeaders64->FileHeader.SizeOfOptionalHeader );
			USHORT SectionNumber = NtHeaders64->FileHeader.NumberOfSections;

			

			PImageSectionInformation SectionStartNode = NULL;
			PImageSectionInformation SectionCurrentNode = NULL;

			
;			for (USHORT i = 0; i < SectionNumber; i++) {
				
				PImageSectionInformation SectionInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(ImageSectionInformation), ImageInformationNode_TAG);
				RtlZeroMemory(SectionInfo, sizeof(ImageSectionInformation));

				// 1. Section Name
				RtlCopyMemory(SectionInfo->SectionName, SectionHeader[i].Name, strlen(SectionHeader[i].Name)+1);

				// 2. Section ImageBaseAddr
				SectionInfo->SectionBaseAddress = (PUCHAR)( (PUCHAR)DllDosHeader + SectionHeader[i].VirtualAddress );

				// 3. Section ImageSize
				SectionInfo->SectionSize = SectionHeader[i].Misc.VirtualSize;

				SectionInfo->NextAddr = NULL;

				if (!SectionStartNode) {
					SectionStartNode = SectionInfo;
					SectionCurrentNode = SectionStartNode;
				}
				else {
					SectionCurrentNode->NextAddr = (PUCHAR)SectionInfo;
					SectionCurrentNode = SectionInfo;
				}
				

			}


			/*
			
			
			
			
			*/


			PImageInformation information = ExAllocatePoolWithTag(NonPagedPool, sizeof(ImageInformation), ImageInformationNode_TAG);

			information->SectionInfo_StartNode = SectionStartNode;


			// 1. Image Name
			// 문자열 버퍼 할당
			USHORT nameLen = LdrEntry->BaseDllName.Length;
			information->ImageName.Length = nameLen;
			information->ImageName.MaximumLength = nameLen + sizeof(WCHAR);
			information->ImageName.Buffer = ExAllocatePoolWithTag(NonPagedPool, information->ImageName.MaximumLength, ImageInformationNode_TAG);

			// 문자열 복사
			if (information->ImageName.Buffer) {
				RtlCopyUnicodeString(&information->ImageName, &LdrEntry->BaseDllName);
			}

			// 2. Image Baseaadress ( Virtual )
			information->Image_BaseAddress = LdrEntry->DllBase;

			// 3. Image of Size
			information->ImageSize = LdrEntry->SizeOfImage;

			information->NextAddr = NULL;


			if (!StartNode) {
				StartNode = information;
				CurrentNode = StartNode;
			}
			else {
				CurrentNode->NextAddr = (PUCHAR)information;
				CurrentNode = information;
			}

			CurrentEntry = CurrentEntry->Flink;
		}
	}

	*output = StartNode;

EXIT1:
	KeUnstackDetachProcess(&APC_STATE);
EXIT0:
	ObDereferenceObject(targetProcess);
	return status;
}
VOID Release_ImageInformation(PImageInformation input) {

	if (input) {
		// 모듈 정보 해제
		PImageInformation current = input;

		while (current) {
			

			// 섹션 메모리 해제
			PImageSectionInformation current_Section = current->SectionInfo_StartNode;
			while (current_Section) {

				PImageSectionInformation Next_Section = (PImageSectionInformation)current_Section->NextAddr;
				ExFreePoolWithTag(current_Section, ImageInformationNode_TAG);

				current_Section = Next_Section;
			}


			if (current->ImageName.Buffer) {
				ExFreePoolWithTag(current->ImageName.Buffer, ImageInformationNode_TAG);
			}

			PImageInformation Next = (PImageInformation)current->NextAddr;
			ExFreePoolWithTag(current, ImageInformationNode_TAG);

			current = Next;
		}
	}


}
