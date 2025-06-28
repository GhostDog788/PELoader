#pragma once  
#include <Windows.h>  
#include "PEParser.h"  
#include "Buffer.h"  
#include <cstdint>

class PELoader {
public:
	class Module
	{
	public:
		explicit Module(HMODULE h = nullptr) noexcept : m_handle(h) {}
		operator HMODULE() const noexcept { return m_handle; }
		HMODULE get() const noexcept { return m_handle; } 
	private:
		HMODULE m_handle;
	};
public:  
	static Module loadLibrary(MemoryLocation image);
	static BOOL freeLibrary(Module image);
	static FARPROC getProcAddress(HMODULE image, LPCSTR proc_name);

	PELoader(MemoryLocation file_image);
	PELoader(Module loaded_image);

	Module getImageBase() const;

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

	void freeTLS();
	void freeImageMemory();

	static DWORD sectionCharacteristicsToProtect(DWORD characteristics);
};