#include <iostream>
#include <string>
#include "../native/windows/ssh_pool_policy.hpp"

int main(int argc, char** argv) {
    try {
        std::vector<uint64_t> ids;
        for (int index = 1; index < argc; ++index) {
            const std::string text = argv[index];
            size_t consumed = 0;
            if (text.empty() || text.find_first_not_of("0123456789") != std::string::npos)
                throw std::runtime_error("Expected a decimal supervisor handle");
            const auto id = std::stoull(text, &consumed);
            if (consumed != text.size())
                throw std::runtime_error("Invalid supervisor handle");
            ids.push_back(id);
        }
        std::cout << ssh_pool_policy::ownedRequest(ids, true).dump() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
