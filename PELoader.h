#pragma once  
#include <Windows.h>  
#include "PEParser.h"  
#include "Buffer.h"  
#include <cstdint>

class PELoader {  
public:  
	static HMODULE loadLibrary(MemoryLocation image);

	PELoader(MemoryLocation image);

	HMODULE getImageBase() const;

private:  
	PEParser m_parser;  
	MemoryLocation m_image_base = nullptr;

	void allocateImageMemory();
	void copyHeadersToMemory();
	void copySectionsToMemory();
	void resolveImports();
};