#include "PELoader.h"
#include "VEHtoSEH.h"
#include "ShadowSEH.h"
#include <stdexcept>

#ifdef _WIN64
#define TLS_PTR_OFFSET 0x58
#else
#define TLS_PTR_OFFSET 0x2c
#endif // _WIN64


PELoader::PELoader(MemoryLocation file_image)
	: m_file_parser(file_image, PEParser::ImageLocation::FILE)
	, m_memory_parser(nullptr, PEParser::ImageLocation::MEMORY)
{
}

PELoader::PELoader(Module loaded_image)
	: m_file_parser(nullptr, PEParser::ImageLocation::FILE)
	, m_memory_parser(reinterpret_cast<MemoryLocation>(loaded_image.get()), PEParser::ImageLocation::MEMORY)
{
}

PELoader::Module PELoader::getImageBase() const
{
	return Module(reinterpret_cast<HMODULE>(m_image_base));
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
				function_address = getProcAddress(lib, reinterpret_cast<LPCSTR>(ordinal));
			}
			else {
				auto import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(m_memory_parser.RVAToMemory(import_name_table[i].u1.ForwarderString));
				function_address = getProcAddress(lib, import_by_name->Name);
			}
			import_address_table[i].u1.AddressOfData = reinterpret_cast<UINT_PTR>(function_address);
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
	UINT_PTR delta = reinterpret_cast<UINT_PTR>(m_image_base) - m_memory_parser.getNtHeaders()->OptionalHeader.ImageBase;
	if (delta == 0) {
		return; // No relocations to process
	}

	SYSTEM_INFO si;
	GetSystemInfo(&si);
	size_t pageSize = si.dwPageSize; // almost always 4096 bytes (0x1000)

	while (reloc_base < reloc_end) {
		auto reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reloc_base);
		DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		WORD* relocData = (WORD*)(reloc + 1);

		DWORD oldProtect1;
		VirtualProtect(m_image_base + reloc->VirtualAddress, pageSize, PAGE_READWRITE, &oldProtect1);
		DWORD oldProtect2;
		VirtualProtect(m_image_base + reloc->VirtualAddress + pageSize, pageSize, PAGE_READWRITE, &oldProtect2);
		// we unprotect BOTH pages to handle address which spans across two pages (FFE, FFF, 000, 001) for
		// example of a DWORD which starts at offset FFE and end in 001 of the next page
		for (DWORD i = 0; i < count; i++) {
			WORD type = relocData[i] >> 12;
			WORD offset = relocData[i] & 0x0FFF;

			if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
				auto patchAddr = reinterpret_cast<PUINT_PTR>(m_image_base + reloc->VirtualAddress + offset);
				*patchAddr += delta;
			}
		}
		VirtualProtect(m_image_base + reloc->VirtualAddress, pageSize, oldProtect1, &oldProtect1);
		VirtualProtect(m_image_base + reloc->VirtualAddress + pageSize, pageSize, oldProtect2, &oldProtect2);

		reloc_base += reloc->SizeOfBlock;
	}
}

void PELoader::resolveTLS()  
{  
   IMAGE_TLS_DIRECTORY* tls_directory = m_memory_parser.getTLSDirectory();  
   if (tls_directory == nullptr) {  
       return; // No TLS directory found  
   }  

   DWORD* tls_index = reinterpret_cast<DWORD*>(tls_directory->AddressOfIndex);  
   *tls_index = TlsAlloc();  
   if (*tls_index == TLS_OUT_OF_INDEXES) {  
       throw std::runtime_error("Failed to allocate TLS index");  
   }  

   size_t tls_data_size = tls_directory->SizeOfZeroFill + (tls_directory->EndAddressOfRawData - tls_directory->StartAddressOfRawData);  

   // allocate starting tls data
   void* tls_data = VirtualAlloc(0, tls_data_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
   if (tls_data == nullptr) {
	   throw std::runtime_error("Failed to allocate TLS data");
   }
   ZeroMemory(tls_data, tls_data_size);
   memcpy(  
       tls_data,  
       reinterpret_cast<void*>(tls_directory->StartAddressOfRawData),  
       tls_data_size - tls_directory->SizeOfZeroFill  
   );

   // set this module's tls data to our allocated data
   // [You need to do this for every thread in the process, for now I do this only for the thread how called my PE Loader]
   auto ptr_to_tls_ptr = reinterpret_cast<UINT_PTR**>(reinterpret_cast<char*>(NtCurrentTeb()) + TLS_PTR_OFFSET);
   (*ptr_to_tls_ptr)[*tls_index] = reinterpret_cast<UINT_PTR>(tls_data);

   // call TLS callbacks if any
   auto callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls_directory->AddressOfCallBacks);  
   for (PIMAGE_TLS_CALLBACK* p = callbacks; *p != nullptr; ++p) {  
       PIMAGE_TLS_CALLBACK callback = *p;  
       callback(m_image_base, DLL_PROCESS_ATTACH, nullptr);  
   }
   // [Should call the thread attach and detach as well]
}

void PELoader::resolveExceptions()
{
#ifdef _WIN64

#else
	EnableSEHoverVEH();
#endif
}

void PELoader::callEntryPoint(DWORD ul_reason_for_call)
{
	using DllMainFunc = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

	auto address = m_image_base + m_memory_parser.getNtHeaders()->OptionalHeader.AddressOfEntryPoint;
	DllMainFunc dllMain = reinterpret_cast<DllMainFunc>(address);

	dllMain(reinterpret_cast<HINSTANCE>(address), ul_reason_for_call, nullptr);
}

void PELoader::freeTLS()
{
	IMAGE_TLS_DIRECTORY* tls_directory = m_memory_parser.getTLSDirectory();
	if (tls_directory == nullptr) {
		return; // No TLS directory found  
	}

	// call TLS callbacks if any
	auto callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls_directory->AddressOfCallBacks);
	for (PIMAGE_TLS_CALLBACK* p = callbacks; *p != nullptr; ++p) {
		PIMAGE_TLS_CALLBACK callback = *p;
		callback(m_image_base, DLL_PROCESS_DETACH, nullptr);
	}

	// free static TLS data
	DWORD* tls_index = reinterpret_cast<DWORD*>(tls_directory->AddressOfIndex);

	auto ptr_to_tls_ptr = reinterpret_cast<UINT_PTR**>(reinterpret_cast<char*>(NtCurrentTeb()) + TLS_PTR_OFFSET);
	VirtualFree(reinterpret_cast<void*>((*ptr_to_tls_ptr)[*tls_index]), 0, MEM_RELEASE);
	(*ptr_to_tls_ptr)[*tls_index] = 0; // This is the core line that prevents the loader to crash undeterminably at the end of the process

	TlsFree(*tls_index);
}

void PELoader::freeExceptions()
{
#ifdef _WIN64

#else
	DisableSEHoverVEH();
#endif
}

void PELoader::freeImageMemory()
{
	VirtualFree(reinterpret_cast<void*>(m_image_base), 0, MEM_RELEASE);
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

PELoader::Module PELoader::loadLibrary(MemoryLocation image)
{
	PELoader loader(image);
	loader.allocateImageMemory();
	loader.copyHeadersToMemory();
	loader.copySectionsToMemory();
	loader.resolveImports();
	loader.resolveRelocations();
	loader.resolveTLS();
	loader.resolveExceptions();

	// [V] allocate memory for the entire image as R/W
	// [V] copy headers: DOS , NT, sections
	// [V] copy each section to memory, change permissions to characteristics
	// 
	// [V] resolve imports
	// [V] resolve relocations
	// [V] resolve exports (getProcAddress)
	// [V] resolve TLS (if present)
	// [V] resolve exception handlers
	// 
	// [V] call entry point
	loader.callEntryPoint(DLL_PROCESS_ATTACH);

	return loader.getImageBase();
}

BOOL PELoader::freeLibrary(PELoader::Module image)
{
	PELoader loader(image);

	loader.freeExceptions();
	loader.freeTLS();
	loader.freeImageMemory();

	return true;
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
		std::string forwarder_string(reinterpret_cast<char*>(reinterpret_cast<UINT_PTR>(image) + rva));
		auto forwarded_dll = forwarder_string.substr(0, forwarder_string.find_first_of('.'));
		auto forwarded_function = forwarder_string.substr(forwarder_string.find_last_of('.') + 1, forwarder_string.size());

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
