#include "PEParser.h"
#include "HandleGuard.h"
#include "ParserException.h"

PEParser::PEParser(MemoryLocation image_base, ImageLocation location)
	: m_base(image_base), m_location(location)
{
}

IMAGE_DOS_HEADER* PEParser::getDosHeader()
{
	return reinterpret_cast<IMAGE_DOS_HEADER*>(m_base);
}

IMAGE_NT_HEADERS* PEParser::getNtHeaders()
{
	IMAGE_DOS_HEADER* dosHeader = getDosHeader();
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
        throw ParserException("Invalid PE signature in dos header");
	}
	return reinterpret_cast<IMAGE_NT_HEADERS*>(m_base + dosHeader->e_lfanew);
}

IMAGE_DATA_DIRECTORY* PEParser::getDataDirectory(int index)
{
	auto ntHeaders = getNtHeaders();
	if (index < 0 || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
		throw ParserException("Data directory index out of range");
	}
	return &ntHeaders->OptionalHeader.DataDirectory[index];
}

IMAGE_SECTION_HEADER* PEParser::getSection(std::string name)
{
	auto sections = getSections();
	for (auto section : sections)
	{
		auto sectionName = reinterpret_cast<const char*>(section->Name);
		if (strncmp(sectionName, name.c_str(), IMAGE_SIZEOF_SHORT_NAME) == 0)
		{
			return section;
		}
	}
	throw ParserException("Section not found: " + name);
}

std::vector<IMAGE_SECTION_HEADER*> PEParser::getSections()
{
	auto ntHeaders = getNtHeaders();
	auto sectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
		reinterpret_cast<MemoryLocation>(ntHeaders) + sizeof(IMAGE_NT_HEADERS));
	std::vector<IMAGE_SECTION_HEADER*> sections;
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		sections.push_back(sectionHeader);
		sectionHeader++;
	}
	return sections;
}

RVA PEParser::FileOffsetToRVA(FileOffset fileOffset)
{
	auto sections = getSections();
	for (const auto& section : sections)
	{
		FileOffset start = section->PointerToRawData;
		FileOffset end = start + section->SizeOfRawData;
		if (fileOffset >= start && fileOffset < end) {
			return section->VirtualAddress + (fileOffset - start);
		}
	}
	throw ParserException("File offset not found in any section");
}

FileOffset PEParser::RVAToFileOffset(RVA rva)
{
	auto sections = getSections();
	for (const auto& section : sections)
	{
		RVA start = section->VirtualAddress;
		RVA end = start + section->Misc.VirtualSize;
		if (rva >= start && rva < end) {
			return section->PointerToRawData + (rva - start);
		}
	}
	throw ParserException("RVA not found in any section");
}

MemoryLocation PEParser::FileOffsetToMemory(FileOffset fileOffset)
{
	if (m_location == ImageLocation::MEMORY) {
		return m_base + FileOffsetToRVA(fileOffset);
	}
	return m_base + fileOffset;
}

MemoryLocation PEParser::RVAToMemory(RVA rva)
{
	if (m_location == ImageLocation::FILE) {
		return m_base + RVAToFileOffset(rva);
	}
	return m_base + rva;
}

RVA PEParser::MemoryToRVA(MemoryLocation memory)
{
	if (m_location == ImageLocation::FILE) {
		return FileOffsetToRVA(memory - m_base);
	}
	return memory - m_base;
}

FileOffset PEParser::MemoryToFileOffset(MemoryLocation memory)
{
	if (m_location == ImageLocation::MEMORY) {
		return RVAToFileOffset(memory - m_base);
	}
	return memory - m_base;
}

IMAGE_IMPORT_DESCRIPTOR* PEParser::getImportDescriptors()
{
	MemoryLocation location = RVAToMemory(getDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress);
	return reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(location);
}

IMAGE_IMPORT_DESCRIPTOR* PEParser::getImportDescriptor(std::string dll_name)
{
	auto import_descriptors = getImportDescriptors();
	for (int i = 0; import_descriptors[i].Name != 0; ++i)
	{
		auto name_offset = import_descriptors[i].Name;
		auto name = reinterpret_cast<const char*>(m_base + name_offset);
		if (dll_name == name) {
			return &import_descriptors[i];
		}
	}
	throw ParserException("Import descriptor not found for DLL: " + dll_name);
}

IMAGE_EXPORT_DIRECTORY* PEParser::getExportDirectory()
{
	MemoryLocation location = RVAToMemory(getDataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress);
	return reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(location);
}
