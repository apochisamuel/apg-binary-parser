
#ifndef APG_INTERNAL_H
#define APG_INTERNAL_H
#include "types.h"
#include "lib.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void apg_context_init(APG_Context *ctx);
void apg_set_error(APG_Context *ctx, int code, const char *msg);
void apg_set_fatal(APG_Context *ctx, int code, const char *msg);
int apg_has_fatal(const APG_Context *ctx);

void apg_reader_init(APG_Reader *r, const uint8_t *data, size_t size);
uint8_t apg_read_u8(APG_Reader *r);
uint16_t apg_read_u16(APG_Reader *r);
uint32_t apg_read_u32(APG_Reader *r);
int apg_read_bytes(APG_Reader *r, uint8_t *out, size_t n);
int apg_reader_seek(APG_Reader *r, size_t pos);
size_t apg_reader_remaining(const APG_Reader *r);

uint32_t apg_hash_bytes(const uint8_t *data, size_t n);
uint32_t apg_mix_u32(uint32_t a, uint32_t b);
uint32_t apg_rotl32(uint32_t v, unsigned s);
uint32_t apg_checksum_window(const uint8_t *data, size_t n, uint32_t seed);
uint32_t apg_score_name(const char *s, size_t n);

int apg_parse_header(APG_Document *doc, const uint8_t *data, size_t size);
int apg_parse_directory(APG_Document *doc, const uint8_t *data, size_t size);
int apg_capture_raw_sections(APG_Document *doc, const uint8_t *data, size_t size);
int apg_load_string_tables(APG_Document *doc);
int apg_parse_attributes(APG_Document *doc);
int apg_parse_symbols(APG_Document *doc);
int apg_parse_relocations(APG_Document *doc);
int apg_parse_frames(APG_Document *doc);
int apg_parse_keyframes(APG_Document *doc);
int apg_parse_streams(APG_Document *doc);
int apg_parse_aliases(APG_Document *doc);
int apg_validate_document(APG_Document *doc);
int apg_resolve_document(APG_Document *doc);
int apg_build_cache(APG_Document *doc);
void apg_free_cache(APG_Document *doc);
void apg_free_strings(APG_StringTable *tab);
void apg_free_attrs(APG_AttrTable *tab);
void apg_free_symbols(APG_SymbolTable *tab);
void apg_free_relocs(APG_RelocTable *tab);
void apg_free_frames(APG_FrameTable *tab);
void apg_free_keyframes(APG_KeyframeTable *tab);
void apg_free_streams(APG_StreamTable *tab);
void apg_free_aliases(APG_AliasList *list);
APG_RawSection *apg_find_raw_section(APG_Document *doc, uint16_t type);
APG_RawSection *apg_raw_section_by_index(APG_Document *doc, uint32_t index);
const APG_DirectoryEntry *apg_directory_by_type(const APG_Document *doc, uint16_t type);
uint32_t apg_resolve_symbol_names(APG_Document *doc);
uint32_t apg_apply_relocations(APG_Document *doc);
uint32_t apg_materialize_streams(APG_Document *doc);
uint32_t apg_cache_build_name_index(APG_Document *doc);
void apg_cache_track_alias(APG_Document *doc, APG_AliasBlob *blob);
void apg_cache_borrow_alias_view(APG_Document *doc, uint8_t *bytes, uint32_t len);
void apg_unwind_alias_entries(APG_Document *doc);
uint32_t apg_directory_frame_budget(const APG_Document *doc, const APG_DirectoryEntry *de, uint32_t payload_len);
APG_RawSection *apg_directory_validate_reloc_source(APG_Document *doc, uint32_t index);
uint32_t apg_reloc_post_validate(APG_Document *doc);
void apg_rollback_attr_table(APG_Document *doc);
void apg_rollback_string_table(APG_Document *doc);
void apg_rollback_keyframes(APG_Document *doc);
APG_DirectoryEntry *apg_directory_mut(APG_Document *doc, uint32_t idx);




/* writer.c */
APG_Writer *apg_writer_create(uint32_t flags);
void apg_writer_free(APG_Writer *w);

/* schema.c */
APG_Schema *apg_schema_create(void);
void apg_schema_free(APG_Schema *s);

/* intern.c */
APG_Intern *apg_intern_create(void);
void apg_intern_free(APG_Intern *t);

/* iterator.c */
/* see iterator.c for full API */

/* inspector.c */
/* see inspector.c for full API */

/* diff.c */
/* see diff.c for full API */

/* integrity.c */
uint32_t apg_crc32(const uint8_t *data, size_t len);
uint32_t apg_integrity_score(const APG_Document *doc);

/* graph.c */
void apg_graph_free(APG_Graph *g);

#endif
