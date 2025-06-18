#pragma once  
#include <Windows.h>  
#include "PEParser.h"  
#include "Buffer.h"  
#include <cstdint>

class PELoader {  
public:  
	static HMODULE loadLibrary(MemoryLocation image);
	static FARPROC getProcAddress(HMODULE image, LPCSTR proc_name);

	PELoader(MemoryLocation image);

	HMODULE getImageBase() const;

private:  
	PEParser m_file_parser;
	PEParser m_memory_parser;
	MemoryLocation m_image_base = nullptr;

	void allocateImageMemory();
	void copyHeadersToMemory();
	void copySectionsToMemory();
	void resolveImports();
	void resolveRelocations();
	void resolveTLS();


	void callEntryPoint(DWORD ul_reason_for_call);

	static DWORD sectionCharacteristicsToProtect(DWORD characteristics);
};