#include <stdint.h>
#include <stddef.h>
#include "lib.h"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 64 || size > 16*1024*1024) return 0;
    APG_Document *doc = apg_open_memory(data, size, 1);
    if (doc) {
        volatile uint32_t n = apg_document_symbol_count(doc);
        n += apg_document_warning_count(doc);
        const char *s = apg_document_string(doc, 0);
        if (s) n ^= (uint32_t)(unsigned char)s[0];
        (void)n;
        apg_close(doc);
    }
    return 0;
}
