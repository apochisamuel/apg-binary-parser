
#ifndef APG_TYPES_H
#define APG_TYPES_H
#include <stddef.h>
#include <stdint.h>

#define APG_MAGIC 0x31475041u
#define APG_VERSION 1u
#define APG_MAX_DIRECTORY 128u
#define APG_MAX_SECTION_SIZE (64u * 1024u * 1024u)
#define APG_SECTION_STRINGS 1u
#define APG_SECTION_ATTRS 2u
#define APG_SECTION_SYMBOLS 3u
#define APG_SECTION_RELOCS 4u
#define APG_SECTION_FRAMES 5u
#define APG_SECTION_KEYFRAMES 6u
#define APG_SECTION_STREAMS 7u
#define APG_SECTION_ALIAS 8u
#define APG_SECTION_ALIASES 8u
#define APG_SECTION_NOTES 9u
#define APG_FLAG_RELAXED 0x0001u
#define APG_FLAG_ROLLBACK_ATTRS 0x0100u
#define APG_FLAG_ROLLBACK_STRINGS 0x0200u
#define APG_FLAG_ALIAS_UNWIND 0x0400u
#define APG_FLAG_TYPE_SWEEP 0x0800u
#define APG_FLAG_KEY_UNWIND 0x1000u
#define APG_FLAG_FRAME_TRUST 0x2000u
#define APG_ERR_NONE 0
#define APG_ERR_FORMAT 1
#define APG_ERR_RANGE 2
#define APG_ERR_ALLOC 3
#define APG_ERR_TRUNCATED 4
#define APG_ERR_INTEGRITY 5

typedef struct APG_Context APG_Context;
typedef struct APG_Document APG_Document;

typedef struct APG_Reader {
    const uint8_t *data;
    size_t size;
    size_t pos;
    int failed;
} APG_Reader;

typedef struct APG_Header {
    uint32_t magic;
    uint16_t version;
    uint16_t directory_count;
    uint32_t flags;
    uint32_t directory_offset;
    uint32_t file_id;
    uint32_t timeline_seed;
    uint32_t reserved_a;
    uint32_t reserved_b;
} APG_Header;

typedef struct APG_DirectoryEntry {
    uint16_t type;
    uint16_t subtype;
    uint32_t offset;
    uint32_t size;
    uint32_t aux;
    uint32_t link;
    uint32_t count;
} APG_DirectoryEntry;

typedef struct APG_RawSection {
    uint16_t type;
    uint16_t subtype;
    uint32_t offset;
    uint32_t size;
    uint8_t *data;
} APG_RawSection;

typedef struct APG_String {
    char *data;
    uint32_t length;
    uint32_t hash;
} APG_String;

typedef struct APG_StringTable {
    APG_String *items;
    uint32_t count;
    uint32_t directory_index;
    uint8_t rolled_back;
} APG_StringTable;

typedef struct APG_Attr {
    uint32_t name_index;
    uint32_t value;
    uint32_t flags;
} APG_Attr;

typedef struct APG_AttrTable {
    APG_Attr *items;
    uint32_t count;
    uint32_t directory_index;
    uint8_t rolled_back;
} APG_AttrTable;

typedef struct APG_Symbol {
    uint32_t name_index;
    uint32_t attr_index;
    uint16_t klass;
    uint16_t flags;
    uint32_t aux;
    APG_String *name_ref;
    APG_Attr *cached_attr;
    uint32_t derived_score;
} APG_Symbol;

typedef struct APG_SymbolTable {
    APG_Symbol *items;
    uint32_t count;
    uint32_t directory_index;
} APG_SymbolTable;

typedef struct APG_Reloc {
    uint32_t section_index;
    uint32_t symbol_index;
    uint32_t target;
    uint32_t flags;
    uint32_t resolved_hash;
} APG_Reloc;

typedef struct APG_RelocTable {
    APG_Reloc *items;
    uint32_t count;
    uint32_t directory_index;
} APG_RelocTable;

typedef struct APG_Frame {
    uint8_t *payload;
    uint32_t payload_len;
    uint32_t storage_len;
    uint32_t mode;
    uint32_t checksum;
} APG_Frame;

typedef struct APG_FrameTable {
    APG_Frame *items;
    uint32_t count;
    uint32_t directory_index;
} APG_FrameTable;

typedef struct APG_Keyframe {
    uint32_t frame_no;
    uint32_t name_index;
    uint32_t marker;
    APG_String *label;
} APG_Keyframe;

typedef struct APG_KeyframeTable {
    APG_Keyframe *items;
    uint32_t count;
    uint32_t directory_index;
    uint8_t rolled_back;
} APG_KeyframeTable;

typedef struct APG_Stream {
    uint32_t id;
    uint32_t key_index;
    uint32_t event_count;
    uint32_t flags;
    APG_Keyframe *key_cache;
    uint32_t materialized_score;
} APG_Stream;

typedef struct APG_StreamTable {
    APG_Stream *items;
    uint32_t count;
    uint32_t directory_index;
} APG_StreamTable;

typedef struct APG_AliasBlob {
    uint32_t id;
    uint32_t size;
    uint8_t *bytes;
} APG_AliasBlob;

typedef struct APG_AliasList {
    APG_AliasBlob **items;
    uint32_t count;
    uint32_t capacity;
} APG_AliasList;

typedef struct APG_Cache {
    APG_StringTable *primary_strings;
    APG_AttrTable *attrs;
    APG_String **name_index;
    uint32_t name_count;
    APG_AliasBlob **owned_aliases;
    uint32_t owned_alias_count;
    uint32_t owned_alias_capacity;
    uint8_t **alias_views;
    uint32_t *alias_view_lens;
    uint32_t alias_view_count;
    uint32_t alias_view_cap;
    uint32_t combined_hash;
    uint32_t integrity_score;
} APG_Cache;

struct APG_Context {
    int error_code;
    int fatal;
    char message[160];
};

struct APG_Document {
    APG_Context ctx;
    APG_Header header;
    APG_DirectoryEntry *directory;
    uint32_t directory_count;
    APG_RawSection *raw_sections;
    uint32_t raw_count;
    APG_StringTable strings;
    APG_AttrTable attrs;
    APG_SymbolTable symbols;
    APG_RelocTable relocs;
    APG_FrameTable frames;
    APG_KeyframeTable keyframes;
    APG_StreamTable streams;
    APG_AliasList aliases;
    APG_Cache cache;
    uint32_t summary_hash;
    uint32_t warning_count;
};


/* forward declarations for extension modules */
struct APG_Query {
    const APG_Document *doc;
    const char *name_pattern;
    uint32_t name_len;
    uint16_t class_mask;
    uint32_t aux_threshold;
    uint32_t attr_lo;
    uint32_t attr_hi;
    uint32_t *hits;
    uint32_t hit_count;
    uint32_t hit_cap;
    uint32_t cursor;
};
typedef struct APG_Query APG_Query;
typedef struct APG_Index APG_Index;
typedef struct APG_Writer APG_Writer;
typedef struct APG_Schema APG_Schema;
typedef struct APG_Intern APG_Intern;
typedef struct APG_Graph APG_Graph;
typedef struct APG_Pool APG_Pool;
typedef struct APG_Filter APG_Filter;
typedef struct APG_Catalog APG_Catalog;

#endif
