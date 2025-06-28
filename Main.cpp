#include <iostream>
#include "HandleGuard.h"
#include <Windows.h>
#include "IoUtils.h"
#include "PELoader.h"
#include "ParserException.h"

int main()
{
#ifdef _WIN64
	auto filename = L"C:\\Users\\dor\\source\\repos\\PELoader\\x64\\Release\\TestDLL.dll";
#else
	auto filename = L"C:\\Users\\dor\\source\\repos\\PELoader\\Release\\TestDLL.dll";
#endif // _WIN64
	try {
		Buffer buffer = IoUtils::readFile(filename);
		//auto lib = LoadLibrary(filename);
		auto lib = PELoader::loadLibrary(buffer.data());

		auto res = PELoader::getProcAddress(lib, "TestTls");
		auto TestTls = reinterpret_cast<void(*)()>(res);
		TestTls();

		PELoader::freeLibrary(lib);
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