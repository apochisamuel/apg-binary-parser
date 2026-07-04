#include "apg_writer.h"
int main(int argc, char **argv) {
    const char *base = argc > 1 ? argv[1] : "fuzz/corpus";
    char path[512];
    const char *names[] = {"root", "track", "gain"};
    uint32_t an[] = {0,1}; uint32_t av[] = {10,22}; uint32_t af[] = {0,0};
    uint32_t sn[] = {0,1}; uint32_t sa[] = {0,1};
    PocFile f; poc_init(&f, 0);
    poc_add(&f, APG_SECTION_STRINGS, 0, 0xffffffffu, 3, strings_payload(3, names));
    poc_add(&f, APG_SECTION_ATTRS, 0, 0xffffffffu, 2, attrs_payload(2, an, av, af));
    poc_add(&f, APG_SECTION_SYMBOLS, 0, 0xffffffffu, 2, symbols_payload(2, sn, sa));
    poc_add(&f, APG_SECTION_FRAMES, 32, 0xffffffffu, 1, frames_payload(24, 4));
    snprintf(path, sizeof(path), "%s/parse_fuzzer/minimal.apg", base); poc_write(&f, path);
    poc_init(&f, 0);
    poc_add(&f, APG_SECTION_STRINGS, 0, 0xffffffffu, 3, strings_payload(3, names));
    poc_add(&f, APG_SECTION_ATTRS, 0, 0xffffffffu, 2, attrs_payload(2, an, av, af));
    poc_add(&f, APG_SECTION_SYMBOLS, 0, 0xffffffffu, 2, symbols_payload(2, sn, sa));
    snprintf(path, sizeof(path), "%s/entry_fuzzer/entries.apg", base); poc_write(&f, path);
    uint32_t rs[] = {2}; uint32_t ri[] = {0};
    poc_init(&f, 0);
    poc_add(&f, APG_SECTION_STRINGS, 0, 0xffffffffu, 3, strings_payload(3, names));
    poc_add(&f, APG_SECTION_ATTRS, 0, 0xffffffffu, 2, attrs_payload(2, an, av, af));
    poc_add(&f, APG_SECTION_SYMBOLS, 0, 0xffffffffu, 2, symbols_payload(2, sn, sa));
    poc_add(&f, APG_SECTION_RELOCS, 0, 0xffffffffu, 1, relocs_payload(1, rs, ri));
    snprintf(path, sizeof(path), "%s/resolve_fuzzer/resolve.apg", base); poc_write(&f, path);
    return 0;
}
