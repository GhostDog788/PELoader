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
		reinterpret_cast<void*>(image_base + 0x10000000), // test relocations
		image_size,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);

	if (new_image_base == nullptr) {
		throw std::runtime_error("Failed to allocate memory for the image");
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

void PELoader::resolveRelocations()
{
	IMAGE_DATA_DIRECTORY* relocations_directory = m_memory_parser.getDataDirectory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
	MemoryLocation reloc_base = m_memory_parser.RVAToMemory(relocations_directory->VirtualAddress);
	MemoryLocation reloc_end = reloc_base + relocations_directory->Size;
#ifdef _WIN64
	QWORD delta = reinterpret_cast<QWORD>(m_image_base) - m_memory_parser.getNtHeaders()->OptionalHeader.ImageBase;
#else
	DWORD delta = reinterpret_cast<DWORD>(m_image_base) - m_memory_parser.getNtHeaders()->OptionalHeader.ImageBase;
#endif
	if (delta == 0) {
		return; // No relocations to process
	}

	while (reloc_base < reloc_end) {
		auto reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reloc_base);
		DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		WORD* relocData = (WORD*)(reloc + 1);

		DWORD oldProtect;
		VirtualProtect(m_image_base + reloc->VirtualAddress, reloc->SizeOfBlock, PAGE_READWRITE, &oldProtect);
		for (DWORD i = 0; i < count; i++) {
			WORD type = relocData[i] >> 12;
			WORD offset = relocData[i] & 0x0FFF;

			if (type == IMAGE_REL_BASED_HIGHLOW) {
				DWORD* patchAddr = (DWORD*)(m_image_base + reloc->VirtualAddress + offset);
				*patchAddr += delta;
			}
			else if (type == IMAGE_REL_BASED_DIR64) {
#ifdef _WIN64
				QWORD* patchAddr = (QWORD*)(m_image_base + reloc->VirtualAddress + offset);
				*patchAddr += delta;
#endif
			}
		}
		VirtualProtect(m_image_base + reloc->VirtualAddress, reloc->SizeOfBlock, oldProtect, &oldProtect);

		reloc_base += reloc->SizeOfBlock;
	}
}

void PELoader::callEntryPoint(DWORD ul_reason_for_call)
{
	using DllMainFunc = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

	auto address = m_image_base + m_memory_parser.getNtHeaders()->OptionalHeader.AddressOfEntryPoint;
	DllMainFunc dllMain = reinterpret_cast<DllMainFunc>(address);

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
	loader.resolveRelocations();

	// [V] allocate memory for the entire image as R/W
	// [V] copy headers: DOS , NT, sections
	// [V] copy each section to memory, change permissions to characteristics
	// 
	// [V] resolve imports
	// [V] resolve relocations
	// [ ] resolve exports
	// [ ] resolve exception handlers
	// 
	// [V] call entry point
	loader.callEntryPoint(DLL_PROCESS_ATTACH);

	return loader.getImageBase();
}

FARPROC PELoader::getProcAddress(HMODULE image, LPCSTR proc_name)
{
	// optional = mimic windows loader and check if module is loaded
	PEParser parser(reinterpret_cast<MemoryLocation>(image), PEParser::ImageLocation::MEMORY);
	IMAGE_EXPORT_DIRECTORY* export_directory = parser.getExportDirectory();
	if (export_directory == nullptr) {
		throw std::runtime_error("Export directory not found");
	}
	DWORD* names = reinterpret_cast<DWORD*>(parser.RVAToMemory(export_directory->AddressOfNames));
	DWORD* functions = reinterpret_cast<DWORD*>(parser.RVAToMemory(export_directory->AddressOfFunctions));
	WORD* ordinals = reinterpret_cast<WORD*>(parser.RVAToMemory(export_directory->AddressOfNameOrdinals));

	bool is_ordinal = ((reinterpret_cast<uintptr_t>(proc_name) >> 16) == 0);

	DWORD func_index = -1;
	if (is_ordinal) {
		WORD ord =  reinterpret_cast<WORD>(proc_name);
		if (ord < export_directory->Base || ord >= export_directory->Base + export_directory->NumberOfFunctions) {
			return nullptr;
		}
		func_index = ord - export_directory->Base;
	}
	else {
		for (DWORD i = 0; i < export_directory->NumberOfNames; ++i) {
			const char* func_name = reinterpret_cast<char*>(parser.RVAToMemory(names[i]));
			if (strcmp(func_name, proc_name) == 0) {
				func_index = ordinals[i];
				break;
			}
		}
		if (func_index == DWORD(-1)) return nullptr;
	}

	DWORD rva = functions[func_index];
	// forwarder support
	auto export_pointer = parser.getDataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT);
	bool isForwarder = rva >= export_pointer->VirtualAddress && rva < export_pointer->VirtualAddress + export_pointer->Size;
	if (isForwarder) {
		std::string forwarder_string(reinterpret_cast<char*>(rva));
		auto forwarded_dll = forwarder_string.substr(0, forwarder_string.find_first_of('.'));
		auto forwarded_function = forwarder_string.substr(forwarder_string.find_last_of('.'), forwarder_string.size());

		HMODULE forwarded_module = LoadLibraryA((forwarded_dll + ".dll").c_str());
		if (!forwarded_module) {
			return nullptr; // Failed to load the forwarded module
		}

		if (forwarded_function[0] == '#') {
			// If the function is an ordinal
			int ordinal = std::stoi(forwarded_function.substr(1));
			return GetProcAddress(forwarded_module, MAKEINTRESOURCEA(ordinal));
		}
		return getProcAddress(forwarded_module, forwarded_function.c_str());
	}
	return reinterpret_cast<FARPROC>(parser.RVAToMemory(rva));
}
