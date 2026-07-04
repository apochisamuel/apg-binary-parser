#include "lib.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
static uint8_t *read_file(const char *p, size_t *n) {
    FILE *fp = fopen(p, "rb"); assert(fp);
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); rewind(fp);
    uint8_t *b = (uint8_t *)malloc((size_t)sz); assert(b);
    assert(fread(b, 1, (size_t)sz, fp) == (size_t)sz); fclose(fp); *n = (size_t)sz; return b;
}
int main(void) {
    size_t n = 0; uint8_t *b = read_file("fuzz/corpus/parse_fuzzer/minimal.apg", &n);
    APG_Document *doc = apg_open_memory(b, n, 0); assert(doc);
    assert(apg_document_error(doc) == 0);
    assert(apg_document_symbol_count(doc) == 2);
    assert(apg_document_frame_count(doc) == 1);
    assert(apg_document_summary_hash(doc) != 0);
    apg_close(doc); free(b); return 0;
}
