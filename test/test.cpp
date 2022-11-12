#include <filesystem>
#include <iostream>
#include <string>
#include <Windows.h>
#include <chrono>


int main() {

	std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
	try {
		for (const auto& dirEntry : std::filesystem::recursive_directory_iterator(std::string("C:\\"), std::filesystem::directory_options::skip_permission_denied)) {
			//std::cout << dirEntry << std::endl;
		}
	}	
	catch (std::filesystem::filesystem_error e) {
		printf("Error: %s\n", e.what());
	}
	std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
	std::cout << "Time to traverse file system = " << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count() << "[µs]" << std::endl;
}

