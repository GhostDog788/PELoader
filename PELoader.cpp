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

void PELoader::resolveImports()
{
	auto iat_directory = m_parser.getDataDirectory(IMAGE_DIRECTORY_ENTRY_IAT);
	auto iat_in_memory = m_parser.RVAToMemory(iat_directory->VirtualAddress);
	DWORD oldProtect;
	VirtualProtect(iat_in_memory, iat_directory->Size, PAGE_READWRITE, &oldProtect);


	auto descriptor = m_parser.getImportDescriptors();
	while (descriptor->Name != 0)
	{
		auto dll_name = reinterpret_cast<LPCSTR>(m_parser.RVAToMemory(descriptor->Name));
		auto lib = LoadLibraryA(dll_name);
		if (lib == nullptr) {
			throw std::runtime_error("Failed to load library: " + std::string(dll_name));
		}
		auto import_address_table = reinterpret_cast<IMAGE_THUNK_DATA*>(m_parser.RVAToMemory(descriptor->FirstThunk));
		auto import_name_table = reinterpret_cast<IMAGE_THUNK_DATA*>(m_parser.RVAToMemory(descriptor->OriginalFirstThunk));
		for (size_t i = 0; import_name_table[i].u1.AddressOfData != 0; ++i)
		{
			FARPROC function_address = nullptr;
			if (IMAGE_SNAP_BY_ORDINAL(import_name_table[i].u1.Ordinal)) {
				auto ordinal = IMAGE_ORDINAL(import_name_table[i].u1.Ordinal);
				// Resolve the ordinal import here
			}
			else {
				auto import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(m_parser.RVAToMemory(import_name_table[i].u1.ForwarderString));
				function_address = GetProcAddress(lib, import_by_name->Name);
			}
#ifdef _WIN64
			import_address_table[i].u1.AddressOfData = reinterpret_cast<QWORD>(function_address);
#else
			import_address_table[i].u1.AddressOfData = reinterpret_cast<DWORD>(function_address);
#endif
		}
		descriptor++;
	}

	VirtualProtect(iat_in_memory, iat_directory->Size, oldProtect, &oldProtect);
}

HMODULE PELoader::loadLibrary(MemoryLocation image)
{
	PELoader loader(image);
	loader.allocateImageMemory();
	loader.copyHeadersToMemory();
	loader.copySectionsToMemory();
	loader.resolveImports();

	// [V] allocate memory for the entire image as R/W
	// [V] copy headers: DOS , NT, sections
	// [V] copy each section to memory, change permissions to characteristics
	// 
	// [V] resolve imports
	// [ ] resolve relocations
	// [ ] resolve exports
	// [ ] resolve exception handlers
	// 
	// [ ] call entry point

	return loader.getImageBase();
}
