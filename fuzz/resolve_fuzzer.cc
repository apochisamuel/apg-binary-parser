#include <stdint.h>
#include <stddef.h>
#include "lib.h"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 64 || size > 16*1024*1024) return 0;
    APG_Document *doc = apg_open_memory(data, size, 2);
    if (doc) {
        volatile uint32_t h = apg_document_summary_hash(doc);
        h ^= (apg_document_stream_count(doc) << 8);
        h ^= (apg_document_error(doc) << 16);
        (void)h;
        apg_close(doc);
    }
    return 0;
}
