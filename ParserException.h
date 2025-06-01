#pragma once
#include <stdexcept>
#include <string>

class ParserException : public std::runtime_error {
public:
    explicit ParserException(const std::string& msg)
        : std::runtime_error(msg) {}
};
