#include <stdint.h>
#include <string.h>
#include "../ini.h"

int dumper(void *user, const char *section, const char *name, const char *value) {
    return 1;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || data[size - 1] != 0) return 0;

    ini_parse_string((const char *) data, dumper, NULL);

    return 0;
}
