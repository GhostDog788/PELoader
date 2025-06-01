#include "PELoader.h"
#include <stdexcept>


PELoader::PELoader(MemoryLocation image)
	: m_parser(image)
{
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

HMODULE PELoader::loadLibrary(MemoryLocation image)
{
	PELoader loader(image);
	loader.allocateImageMemory();
	loader.copyHeadersToMemory();

	// [V] allocate memory for the entire image as R/W
	// [V] copy headers: DOS , NT, sections
	// [ ] copy each section to memory, change permissions to characteristics
	// 
	// [ ] resolve imports
	// [ ] resolve relocations
	// [ ] resolve exports
	// [ ] resolve exception handlers
	// 
	// [ ] call entry point

	return reinterpret_cast<HMODULE>(loader.m_parser.getDosHeader()); // equal to returning 'image'
}
