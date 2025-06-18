#include <iostream>
#include "HandleGuard.h"
#include <Windows.h>
#include "IoUtils.h"
#include "PELoader.h"
#include "ParserException.h"

int main()
{
	auto filename = L"C:\\Users\\dor\\source\\repos\\PELoader\\Release\\CDLL.dll";
	try {
		Buffer buffer = IoUtils::readFile(filename);
		//auto lib = LoadLibrary(filename);
		auto lib = PELoader::loadLibrary(buffer.data());

		PEParser parser(reinterpret_cast<MemoryLocation>(lib), PEParser::ImageLocation::MEMORY);
		auto desceiptor = parser.getImportDescriptors();
		auto res = PELoader::getProcAddress(lib, (LPCSTR)3);
		auto sub = reinterpret_cast<int(*)(int, int)>(res);
		int x = sub(6, 4);
		int y = 5;
	}
	catch (const ParserException& e) {
		std::cerr << "ParserException: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}
	catch (const std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}
	catch (...) {
		std::cerr << "Unknown exception occurred." << std::endl;
		return EXIT_FAILURE;
	}
}