#include <cassert>
#include <string>

#include "micro_sentinel/json.h"

using namespace micro_sentinel;

namespace {

void ExpectSuccess(const std::string &input, JsonValue::Type type) {
    JsonValue value;
    std::string error;
    bool ok = ParseJson(input, value, error);
    assert(ok && error.empty());
    assert(value.type() == type);
}

void ExpectFailure(const std::string &input) {
    JsonValue value;
    std::string error;
    bool ok = ParseJson(input, value, error);
    assert(!ok);
    assert(!error.empty());
}

} // namespace

void RunJsonTests() {
    ExpectSuccess("null", JsonValue::Type::Null);
    ExpectSuccess("true", JsonValue::Type::Bool);
    ExpectSuccess("42", JsonValue::Type::Number);
    ExpectSuccess("\"text\"", JsonValue::Type::String);
    ExpectSuccess("[]", JsonValue::Type::Array);
    ExpectSuccess("{}", JsonValue::Type::Object);

    {
        JsonValue value;
        std::string error;
        bool ok = ParseJson("{\"num\":42,\"nested\":[\"a\",\"b\"]}", value, error);
        assert(ok);
        const auto &obj = value.AsObject();
        assert(obj.at("num")->AsNumber() == 42);
        const auto &nested = obj.at("nested")->AsArray();
        assert(nested.size() == 2);
        assert(nested[0]->AsString() == "a");
        assert(nested[1]->AsString() == "b");
    }

    {
        JsonValue value;
        std::string error;
        bool ok = ParseJson("[\"line1\\nline2\", {\"flag\":false}]", value, error);
        assert(ok);
        const auto &arr = value.AsArray();
        assert(arr.size() == 2);
        assert(arr[0]->AsString() == "line1\nline2");
        assert(arr[1]->AsObject().at("flag")->AsBool() == false);
    }

    ExpectFailure("{\"unterminated\": [1, 2}");
    ExpectFailure("[1, 2, ");
    ExpectFailure("tru");
}
