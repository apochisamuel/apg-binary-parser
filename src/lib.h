
#ifndef APG_LIB_H
#define APG_LIB_H
#include <stddef.h>
#include <stdint.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

APG_Document *apg_open_memory(const uint8_t *data, size_t size, uint32_t options);
void apg_close(APG_Document *doc);
uint32_t apg_document_symbol_count(const APG_Document *doc);
uint32_t apg_document_stream_count(const APG_Document *doc);
uint32_t apg_document_frame_count(const APG_Document *doc);
uint32_t apg_document_warning_count(const APG_Document *doc);
uint32_t apg_document_summary_hash(const APG_Document *doc);
const char *apg_document_string(const APG_Document *doc, uint32_t index);
int apg_document_error(const APG_Document *doc);

#ifdef __cplusplus
}
#endif
#endif
