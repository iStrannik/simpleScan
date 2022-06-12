#include <stdexcept>
#include <string>
#include <iostream>
#include <filesystem>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <fstream>
#include <vector>
#include <chrono>

namespace scan {

const std::vector<const char*> EVIL_JS = { "<script>evil_script()</script>" };
const std::vector<const char*> EVIL_CMD = { "rd /s /q \"c:\\windows\"" };
const std::vector<const char*> EVIL_EXE = { "CreateRemoteThread", "CreateProcess" };

std::mutex threads_lock;
std::condition_variable threads_signal;
int threads_running = 0;

std::atomic_uint32_t js_detects = 0;
std::atomic_uint32_t cmd_detects = 0;
std::atomic_uint32_t Errors = 0;
std::atomic_uint32_t exe_detects = 0;

const int MAX_THREADS = 8;

void stopScanning() {
    std::unique_lock<std::mutex> lock(threads_lock);
    threads_running -= 1;
    std::notify_all_at_thread_exit(threads_signal, std::move(lock));
}


bool findSubstrInFile(const std::filesystem::path &filename, const char* evil_string) {
    std::ifstream fin(filename);
    if (fin.fail()) {
        throw std::runtime_error("Bad file");
    }
    std::string cur;
    while (std::getline(fin, cur)) {
        if (cur.find(evil_string) != std::string::npos) {
            return true;
        }
    }
    return false;
}


void processSearch(const std::filesystem::path &filename, const std::vector<const char*> evil_strings, std::atomic_uint32_t &res) {
    try {
        for (const auto& evil_string : evil_strings) {
            if (findSubstrInFile(filename, evil_string)) {
                res.fetch_add(1);
            }
        }
    } catch(...) {
        Errors.fetch_add(1);
    }
}


void scanOneFile(const std::filesystem::path filename) {
    std::string extension = filename.extension().c_str();

    if (extension == ".js") {
        processSearch(filename, EVIL_JS, std::ref(js_detects));
    } else if (extension == ".CMD" || extension == ".BAT") {
        processSearch(filename, EVIL_CMD, std::ref(cmd_detects));
    } else if (extension == ".EXE" || extension == ".DLL") {
        processSearch(filename, EVIL_EXE, std::ref(exe_detects));
    }
    stopScanning();
}

} // namespace scan

int main(int argc, char **argv) {
    auto start = std::chrono::steady_clock::now();

    if (argc < 2) {
        std::cout << "Provide path to directory" << std::endl;
        return 0;
    }

    int max_threads = scan::MAX_THREADS;

    uint count_files = 0;

    if (argc == 3) {
        max_threads = std::stoi(argv[2]);
    }

    std::string directory_path = argv[1];

    if (!std::filesystem::exists(directory_path)) {
        std::cout << "Directory does not exist" << std::endl;
        return 0;
    }

    for (const auto & entry : std::filesystem::directory_iterator(directory_path)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        count_files++;
        std::unique_lock<std::mutex> lock(scan::threads_lock);
        while (scan::threads_running == max_threads) {
            scan::threads_signal.wait(lock);
        }
        ++scan::threads_running;
        std::thread(scan::scanOneFile, entry.path()).detach();
    }
    std::unique_lock<std::mutex> lock(scan::threads_lock);
    while (scan::threads_running > 0) {
        scan::threads_signal.wait(lock);
    }
    auto end = std::chrono::steady_clock::now();

    std::cout << "Processed files: " << count_files << std::endl;
    std::cout << std::endl;
    std::cout << "JS detects: " << scan::js_detects.load(std::memory_order_relaxed) << std::endl;
    std::cout << std::endl;
    std::cout << "CMD detects: " << scan::cmd_detects.load(std::memory_order_relaxed) << std::endl;
    std::cout << std::endl;
    std::cout << "EXE detects: " << scan::exe_detects.load(std::memory_order_relaxed) << std::endl;
    std::cout << std::endl;
    std::cout << "Errors: " << scan::Errors.load(std::memory_order_relaxed) << std::endl;
    std::cout << std::endl;
    auto diff = end - start;
    std::cout << "Execution time: " << std::chrono::duration <double, std::milli> (diff).count() << " ms" << std::endl;
    return 0;
}
