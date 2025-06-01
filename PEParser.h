#pragma once
#include "Buffer.h"
#include "LocationTypes.h"
#include <string>
#include <Windows.h>

class PEParser
{
public:
	enum class ImageLocation
	{
		FILE = 0,
		MEMORY = 1
	};
public:
	PEParser(MemoryLocation image_base, ImageLocation location);
	~PEParser() = default;
	PEParser(const PEParser&) = delete;
	PEParser& operator=(const PEParser&) = delete;
	PEParser(PEParser&&) = delete;
	PEParser& operator=(PEParser&&) = default;

	IMAGE_DOS_HEADER* getDosHeader();
	IMAGE_NT_HEADERS* getNtHeaders();
	IMAGE_DATA_DIRECTORY* getDataDirectory(int index);
	IMAGE_SECTION_HEADER* getSection(std::string name);
	std::vector<IMAGE_SECTION_HEADER*> getSections();

	RVA FileOffsetToRVA(FileOffset fileOffset);
	FileOffset RVAToFileOffset(RVA rva);
	MemoryLocation FileOffsetToMemory(FileOffset fileOffset);
	MemoryLocation RVAToMemory(RVA rva);
	RVA MemoryToRVA(MemoryLocation memory);
	FileOffset MemoryToFileOffset(MemoryLocation memory);

	IMAGE_IMPORT_DESCRIPTOR* getImportDescriptors();
	IMAGE_IMPORT_DESCRIPTOR* getImportDescriptor(std::string dll_name);

private:
	MemoryLocation m_base = nullptr;
	ImageLocation m_location;
};

