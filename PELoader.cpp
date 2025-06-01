#include "PELoader.h"
#include <stdexcept>


PELoader::PELoader(MemoryLocation image)
	: m_file_parser(image, PEParser::ImageLocation::FILE)
	, m_memory_parser(m_image_base, PEParser::ImageLocation::MEMORY)
{
}

HMODULE PELoader::getImageBase() const
{
	return reinterpret_cast<HMODULE>(m_image_base);
}

void PELoader::allocateImageMemory()
{
	auto image_size = m_file_parser.getNtHeaders()->OptionalHeader.SizeOfImage;
	auto image_base = m_file_parser.getNtHeaders()->OptionalHeader.ImageBase;
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
	m_memory_parser = PEParser(m_image_base, PEParser::ImageLocation::MEMORY);
}

void PELoader::copyHeadersToMemory()
{
	memcpy(m_image_base, m_file_parser.getDosHeader(), m_file_parser.getNtHeaders()->OptionalHeader.SizeOfHeaders);
}

void PELoader::copySectionsToMemory()
{
	for (auto section : m_file_parser.getSections())
	{
		auto section_data = reinterpret_cast<MemoryLocation>(m_file_parser.FileOffsetToMemory(section->PointerToRawData));
		auto section_destination = reinterpret_cast<MemoryLocation>(m_image_base + section->VirtualAddress);
		memcpy(section_destination, section_data, section->SizeOfRawData);

		DWORD oldProtect;
		if (!VirtualProtect(
			section_destination,
			section->Misc.VirtualSize,
			sectionCharacteristicsToProtect(section->Characteristics),
			&oldProtect
		)) {
			throw std::runtime_error("Failed to change section memory protection");
		}
	}
}

void PELoader::resolveImports()
{
	auto iat_directory = m_memory_parser.getDataDirectory(IMAGE_DIRECTORY_ENTRY_IAT);
	auto iat_in_memory = m_memory_parser.RVAToMemory(iat_directory->VirtualAddress);
	DWORD oldProtect;
	VirtualProtect(iat_in_memory, iat_directory->Size, PAGE_READWRITE, &oldProtect);


	auto descriptor = m_memory_parser.getImportDescriptors();
	while (descriptor->Name != 0)
	{
		auto dll_name = reinterpret_cast<LPCSTR>(m_memory_parser.RVAToMemory(descriptor->Name));
		auto lib = LoadLibraryA(dll_name);
		if (lib == nullptr) {
			throw std::runtime_error("Failed to load library: " + std::string(dll_name));
		}
		auto import_address_table = reinterpret_cast<IMAGE_THUNK_DATA*>(m_memory_parser.RVAToMemory(descriptor->FirstThunk));
		auto import_name_table = reinterpret_cast<IMAGE_THUNK_DATA*>(m_memory_parser.RVAToMemory(descriptor->OriginalFirstThunk));
		for (size_t i = 0; import_name_table[i].u1.AddressOfData != 0; ++i)
		{
			FARPROC function_address = nullptr;
			if (IMAGE_SNAP_BY_ORDINAL(import_name_table[i].u1.Ordinal)) {
				auto ordinal = IMAGE_ORDINAL(import_name_table[i].u1.Ordinal);
				// Resolve the ordinal import here
			}
			else {
				auto import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(m_memory_parser.RVAToMemory(import_name_table[i].u1.ForwarderString));
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

void PELoader::callEntryPoint(DWORD ul_reason_for_call)
{
	using DllMainFunc = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

	PEParser memory_parser(m_image_base, PEParser::ImageLocation::MEMORY);
	auto address = m_image_base + memory_parser.getNtHeaders()->OptionalHeader.AddressOfEntryPoint;
	DllMainFunc dllMain = reinterpret_cast<DllMainFunc>(address);
	auto desc = memory_parser.getImportDescriptor("USER32.dll");
	DWORD message_box = reinterpret_cast<IMAGE_THUNK_DATA*>(memory_parser.RVAToMemory(desc->FirstThunk))->u1.AddressOfData;
	dllMain(reinterpret_cast<HINSTANCE>(address), ul_reason_for_call, nullptr);
}

DWORD PELoader::sectionCharacteristicsToProtect(DWORD characteristics)
{
	bool isExec = characteristics & IMAGE_SCN_MEM_EXECUTE;
	bool isRead = characteristics & IMAGE_SCN_MEM_READ;
	bool isWrite = characteristics & IMAGE_SCN_MEM_WRITE;

	if (isExec) {
		if (isRead) {
			if (isWrite) return PAGE_EXECUTE_READWRITE;
			else return PAGE_EXECUTE_READ;
		}
		return PAGE_EXECUTE;
	}
	else {
		if (isRead) {
			if (isWrite) return PAGE_READWRITE;
			else return PAGE_READONLY;
		}
		if (isWrite) return PAGE_WRITECOPY;
	}
	return PAGE_NOACCESS;
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
	// [V] call entry point
	loader.callEntryPoint(DLL_PROCESS_ATTACH);

	return loader.getImageBase();
}
