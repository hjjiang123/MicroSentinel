#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace micro_sentinel {

class JsonValue {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    JsonValue() = default;
    explicit JsonValue(Type t) : type_(t) {}

    Type type() const { return type_; }
    bool IsNull() const { return type_ == Type::Null; }
    bool IsBool() const { return type_ == Type::Bool; }
    bool IsNumber() const { return type_ == Type::Number; }
    bool IsString() const { return type_ == Type::String; }
    bool IsArray() const { return type_ == Type::Array; }
    bool IsObject() const { return type_ == Type::Object; }

    bool AsBool() const { return bool_value_; }
    double AsNumber() const { return number_value_; }
    const std::string &AsString() const { return string_value_; }
    const std::vector<std::unique_ptr<JsonValue>> &AsArray() const { return array_value_; }
    const std::unordered_map<std::string, std::unique_ptr<JsonValue>> &AsObject() const { return object_value_; }

    std::vector<std::unique_ptr<JsonValue>> &Array() { return array_value_; }
    std::unordered_map<std::string, std::unique_ptr<JsonValue>> &Object() { return object_value_; }

    void SetBool(bool value) {
        type_ = Type::Bool;
        bool_value_ = value;
    }
    void SetNumber(double value) {
        type_ = Type::Number;
        number_value_ = value;
    }
    void SetString(std::string value) {
        type_ = Type::String;
        string_value_ = std::move(value);
    }
    void SetArray() {
        type_ = Type::Array;
        array_value_.clear();
    }
    void SetObject() {
        type_ = Type::Object;
        object_value_.clear();
    }

private:
    Type type_{Type::Null};
    bool bool_value_{false};
    double number_value_{0.0};
    std::string string_value_;
    std::vector<std::unique_ptr<JsonValue>> array_value_;
    std::unordered_map<std::string, std::unique_ptr<JsonValue>> object_value_;
};

bool ParseJson(const std::string &input, JsonValue &out, std::string &error);

} // namespace micro_sentinel
