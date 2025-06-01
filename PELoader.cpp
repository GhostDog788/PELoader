#include "PELoader.h"
#include <stdexcept>


PELoader::PELoader(MemoryLocation image)
	: m_parser(image, PEParser::ImageLocation::FILE)
{
}

HMODULE PELoader::getImageBase() const
{
	return reinterpret_cast<HMODULE>(m_image_base);
}

void PELoader::allocateImageMemory()
{
	auto image_size = m_parser.getNtHeaders()->OptionalHeader.SizeOfImage;
	auto image_base = m_parser.getNtHeaders()->OptionalHeader.ImageBase;
	auto new_image_base = VirtualAlloc(
		reinterpret_cast<void*>(image_base),
		image_size,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);

	if (new_image_base == nullptr) {
		throw std::runtime_error("Failed to allocate memory for the image");
	}
	else if (new_image_base != reinterpret_cast<void*>(image_base)) {
		throw std::runtime_error("Failed to allocate memory at the specified image base");
	}
	m_image_base = reinterpret_cast<MemoryLocation>(new_image_base);
}

void PELoader::copyHeadersToMemory()
{
	memcpy(m_image_base, m_parser.getDosHeader(), m_parser.getNtHeaders()->OptionalHeader.SizeOfHeaders);
}

void PELoader::copySectionsToMemory()
{
	for (auto section : m_parser.getSections())
	{
		auto section_data = reinterpret_cast<MemoryLocation>(m_parser.FileOffsetToMemory(section->PointerToRawData));
		auto section_destination = reinterpret_cast<MemoryLocation>(m_image_base + section->VirtualAddress);
		memcpy(section_destination, section_data, section->SizeOfRawData);

		DWORD oldProtect;
		VirtualProtect(section_destination, section->SizeOfRawData, section->Characteristics, &oldProtect);
	}
}

HMODULE PELoader::loadLibrary(MemoryLocation image)
{
	PELoader loader(image);
	loader.allocateImageMemory();
	loader.copyHeadersToMemory();
	loader.copySectionsToMemory();

	// [V] allocate memory for the entire image as R/W
	// [V] copy headers: DOS , NT, sections
	// [V] copy each section to memory, change permissions to characteristics
	// 
	// [ ] resolve imports
	// [ ] resolve relocations
	// [ ] resolve exports
	// [ ] resolve exception handlers
	// 
	// [ ] call entry point

	return loader.getImageBase();
}
