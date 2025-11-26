#include "micro_sentinel/json.h"

#include <cctype>
#include <memory>

namespace micro_sentinel {

namespace {

class Parser {
public:
    Parser(const std::string &input, std::string &error)
        : input_(input), error_(error) {}

    bool Parse(JsonValue &value) {
        SkipWhitespace();
        if (!ParseValue(value))
            return false;
        SkipWhitespace();
        return pos_ == input_.size();
    }

private:
    bool ParseValue(JsonValue &value) {
        SkipWhitespace();
        if (pos_ >= input_.size()) {
            error_ = "Unexpected end of input";
            return false;
        }
        char c = input_[pos_];
        if (c == 'n')
            return ParseNull(value);
        if (c == 't' || c == 'f')
            return ParseBool(value);
        if (c == '"')
            return ParseString(value);
        if (c == '[')
            return ParseArray(value);
        if (c == '{')
            return ParseObject(value);
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c)))
            return ParseNumber(value);
        error_ = "Unexpected token";
        return false;
    }

    bool ParseNull(JsonValue &value) {
        if (input_.compare(pos_, 4, "null") != 0) {
            error_ = "Invalid token (expected null)";
            return false;
        }
        pos_ += 4;
        value = JsonValue{};
        return true;
    }

    bool ParseBool(JsonValue &value) {
        if (input_.compare(pos_, 4, "true") == 0) {
            pos_ += 4;
            value.SetBool(true);
            return true;
        }
        if (input_.compare(pos_, 5, "false") == 0) {
            pos_ += 5;
            value.SetBool(false);
            return true;
        }
        error_ = "Invalid boolean literal";
        return false;
    }

    bool ParseString(JsonValue &value) {
        std::string out;
        if (!ParseRawString(out))
            return false;
        value.SetString(out);
        return true;
    }

    bool ParseRawString(std::string &out) {
        if (input_[pos_] != '"')
            return false;
        ++pos_;
        out.clear();
        while (pos_ < input_.size()) {
            char c = input_[pos_++];
            if (c == '"')
                return true;
            if (c == '\\') {
                if (pos_ >= input_.size()) {
                    error_ = "Invalid escape sequence";
                    return false;
                }
                char esc = input_[pos_++];
                switch (esc) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                default:
                    error_ = "Unsupported escape sequence";
                    return false;
                }
            } else {
                out.push_back(c);
            }
        }
        error_ = "Unterminated string literal";
        return false;
    }

    bool ParseNumber(JsonValue &value) {
        size_t start = pos_;
        if (input_[pos_] == '-')
            ++pos_;
        if (pos_ >= input_.size()) {
            error_ = "Unexpected end in number";
            return false;
        }
        if (input_[pos_] == '0') {
            ++pos_;
        } else if (std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
            while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_])))
                ++pos_;
        } else {
            error_ = "Invalid number";
            return false;
        }
        if (pos_ < input_.size() && input_[pos_] == '.') {
            ++pos_;
            if (pos_ >= input_.size() || !std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
                error_ = "Invalid fractional part";
                return false;
            }
            while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_])))
                ++pos_;
        }
        if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-'))
                ++pos_;
            if (pos_ >= input_.size() || !std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
                error_ = "Invalid exponent";
                return false;
            }
            while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_])))
                ++pos_;
        }
        double number = 0.0;
        try {
            number = std::stod(input_.substr(start, pos_ - start));
        } catch (...) {
            error_ = "Failed to parse number";
            return false;
        }
        value.SetNumber(number);
        return true;
    }

    bool ParseArray(JsonValue &value) {
        if (input_[pos_] != '[')
            return false;
        ++pos_;
        value.SetArray();
        SkipWhitespace();
        if (pos_ < input_.size() && input_[pos_] == ']') {
            ++pos_;
            return true;
        }
        while (pos_ < input_.size()) {
            auto element = std::make_unique<JsonValue>();
            if (!ParseValue(*element))
                return false;
            value.Array().push_back(std::move(element));
            SkipWhitespace();
            if (pos_ >= input_.size())
                break;
            char c = input_[pos_++];
            if (c == ']')
                return true;
            if (c != ',') {
                error_ = "Expected ',' or ']' in array";
                return false;
            }
            SkipWhitespace();
        }
        error_ = "Unterminated array";
        return false;
    }

    bool ParseObject(JsonValue &value) {
        if (input_[pos_] != '{')
            return false;
        ++pos_;
        value.SetObject();
        SkipWhitespace();
        if (pos_ < input_.size() && input_[pos_] == '}') {
            ++pos_;
            return true;
        }
        while (pos_ < input_.size()) {
            std::string key;
            if (!ParseRawString(key)) {
                error_ = "Expected string key";
                return false;
            }
            SkipWhitespace();
            if (pos_ >= input_.size() || input_[pos_] != ':') {
                error_ = "Expected ':' after key";
                return false;
            }
            ++pos_;
            SkipWhitespace();
            auto child = std::make_unique<JsonValue>();
            if (!ParseValue(*child))
                return false;
            value.Object().emplace(std::move(key), std::move(child));
            SkipWhitespace();
            if (pos_ >= input_.size())
                break;
            char c = input_[pos_++];
            if (c == '}')
                return true;
            if (c != ',') {
                error_ = "Expected ',' or '}' in object";
                return false;
            }
            SkipWhitespace();
        }
        error_ = "Unterminated object";
        return false;
    }

    void SkipWhitespace() {
        while (pos_ < input_.size() && std::isspace(static_cast<unsigned char>(input_[pos_])))
            ++pos_;
    }

    const std::string &input_;
    std::string &error_;
    size_t pos_{0};
};

} // namespace

bool ParseJson(const std::string &input, JsonValue &out, std::string &error) {
    Parser parser(input, error);
    return parser.Parse(out);
}

} // namespace micro_sentinel
