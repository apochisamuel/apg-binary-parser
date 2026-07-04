
#include "internal.h"

/*
 * compress.c — lightweight payload compression: run-length encoding
 * and delta encoding for section data.
 *
 * RLE format: [count:u8] [byte:u8] pairs.  count==0 is a literal run
 * whose length follows as the next byte.
 *
 * Delta encoding: first byte stored verbatim, subsequent bytes stored
 * as signed deltas from the previous byte.  Good for sorted or
 * slowly-varying data like symbol aux fields.
 */

/* ---- RLE encode ---- */
uint8_t *apg_rle_encode(const uint8_t *data, uint32_t len, uint32_t *out_len) {
    if (!data || !len) { if (out_len) *out_len = 0; return NULL; }
    size_t cap = (size_t)len * 2u + 4u;
    uint8_t *out = (uint8_t *)malloc(cap);
    if (!out) { if (out_len) *out_len = 0; return NULL; }
    uint32_t oi = 0;
    uint32_t i = 0;
    while (i < len) {
        /* count run */
        uint8_t val = data[i];
        uint32_t run = 1;
        while (i + run < len && data[i + run] == val && run < 255) run++;
        if (run >= 3) {
            /* encoded run */
            out[oi++] = (uint8_t)run;
            out[oi++] = val;
            i += run;
        } else {
            /* literal run: gather non-repeating bytes */
            uint32_t lit_start = i;
            uint32_t lit_len = 0;
            while (i + lit_len < len && lit_len < 255) {
                uint32_t peek = 1;
                while (i + lit_len + peek < len &&
                       data[i + lit_len + peek] == data[i + lit_len] &&
                       peek < 3) peek++;
                if (peek >= 3) break;
                lit_len++;
            }
            if (lit_len == 0) lit_len = 1;
            out[oi++] = 0;          /* literal marker */
            out[oi++] = (uint8_t)lit_len;
            for (uint32_t j = 0; j < lit_len; j++) out[oi++] = data[lit_start + j];
            i = lit_start + lit_len;
        }
    }
    if (out_len) *out_len = oi;
    return out;
}

/* ---- RLE decode ---- */
uint8_t *apg_rle_decode(const uint8_t *enc, uint32_t enc_len, uint32_t *out_len) {
    if (!enc || !enc_len) { if (out_len) *out_len = 0; return NULL; }
    /* first pass: compute output size */
    uint32_t total = 0;
    uint32_t i = 0;
    while (i + 1 < enc_len) {
        uint8_t tag = enc[i++];
        if (tag == 0) {
            if (i >= enc_len) break;
            uint8_t lit = enc[i++];
            total += lit;
            i += lit;
        } else {
            total += tag;
            i++;
        }
    }
    uint8_t *out = (uint8_t *)malloc(total ? total : 1u);
    if (!out) { if (out_len) *out_len = 0; return NULL; }
    /* second pass: decode */
    uint32_t oi = 0;
    i = 0;
    while (i + 1 < enc_len && oi < total) {
        uint8_t tag = enc[i++];
        if (tag == 0) {
            if (i >= enc_len) break;
            uint8_t lit = enc[i++];
            for (uint8_t j = 0; j < lit && oi < total && i < enc_len; j++)
                out[oi++] = enc[i++];
        } else {
            uint8_t val = enc[i++];
            for (uint8_t j = 0; j < tag && oi < total; j++) out[oi++] = val;
        }
    }
    if (out_len) *out_len = oi;
    return out;
}

/* ---- delta encode ---- */
uint8_t *apg_delta_encode(const uint8_t *data, uint32_t len, uint32_t *out_len) {
    if (!data || !len) { if (out_len) *out_len = 0; return NULL; }
    uint8_t *out = (uint8_t *)malloc(len);
    if (!out) { if (out_len) *out_len = 0; return NULL; }
    out[0] = data[0];
    for (uint32_t i = 1; i < len; i++)
        out[i] = (uint8_t)(data[i] - data[i-1]);
    if (out_len) *out_len = len;
    return out;
}

/* ---- delta decode ---- */
uint8_t *apg_delta_decode(const uint8_t *enc, uint32_t len, uint32_t *out_len) {
    if (!enc || !len) { if (out_len) *out_len = 0; return NULL; }
    uint8_t *out = (uint8_t *)malloc(len);
    if (!out) { if (out_len) *out_len = 0; return NULL; }
    out[0] = enc[0];
    for (uint32_t i = 1; i < len; i++)
        out[i] = (uint8_t)(out[i-1] + enc[i]);
    if (out_len) *out_len = len;
    return out;
}

void apg_compress_free(uint8_t *buf) { free(buf); }

/* ---- compression ratio estimate ---- */
double apg_compression_ratio(const uint8_t *data, uint32_t len) {
    if (!data || !len) return 1.0;
    uint32_t enc_len = 0;
    uint8_t *enc = apg_rle_encode(data, len, &enc_len);
    if (!enc) return 1.0;
    double ratio = (double)enc_len / (double)len;
    free(enc);
    return ratio;
}


/* ---- LZ77-style sliding window compression ---- */

#define LZ_WINDOW  4096u
#define LZ_LOOK    258u
#define LZ_MIN_MATCH 3u

typedef struct LZMatch {
    uint32_t offset;
    uint32_t length;
} LZMatch;

static LZMatch apg_lz_find_match(const uint8_t *data, uint32_t pos,
                                   uint32_t len, uint32_t window) {
    LZMatch best = {0, 0};
    uint32_t start = (pos > window) ? pos - window : 0;
    uint32_t max_len = len - pos;
    if (max_len > LZ_LOOK) max_len = LZ_LOOK;
    for (uint32_t s = start; s < pos; s++) {
        uint32_t ml = 0;
        while (ml < max_len && data[s + ml] == data[pos + ml]) ml++;
        if (ml >= LZ_MIN_MATCH && ml > best.length) {
            best.offset = pos - s;
            best.length = ml;
        }
    }
    return best;
}

uint8_t *apg_lz_compress(const uint8_t *data, uint32_t len, uint32_t *out_len) {
    if (!data || !len) { if (out_len) *out_len = 0; return NULL; }
    size_t cap = (size_t)len + len / 8 + 64;
    uint8_t *out = (uint8_t *)malloc(cap);
    if (!out) { if (out_len) *out_len = 0; return NULL; }
    /* output format: flag byte (8 tokens), each token is either:
       flag=0: literal byte (1 byte)
       flag=1: (offset:u16, length:u8) back-reference */
    uint32_t oi = 0, i = 0;
    while (i < len) {
        /* reserve space for flag byte */
        if (oi + 1 >= cap) { cap *= 2; uint8_t *p = (uint8_t*)realloc(out, cap); if (!p) break; out = p; }
        uint32_t flag_pos = oi++;
        uint8_t flags = 0;
        for (int bit = 0; bit < 8 && i < len; bit++) {
            LZMatch m = apg_lz_find_match(data, i, len, LZ_WINDOW);
            if (m.length >= LZ_MIN_MATCH) {
                flags |= (1u << bit);
                if (oi + 3 >= cap) { cap *= 2; uint8_t *p = (uint8_t*)realloc(out, cap); if (!p) goto done; out = p; }
                out[oi++] = (uint8_t)(m.offset & 0xff);
                out[oi++] = (uint8_t)(m.offset >> 8);
                out[oi++] = (uint8_t)(m.length - LZ_MIN_MATCH);
                i += m.length;
            } else {
                if (oi + 1 >= cap) { cap *= 2; uint8_t *p = (uint8_t*)realloc(out, cap); if (!p) goto done; out = p; }
                out[oi++] = data[i++];
            }
        }
        out[flag_pos] = flags;
    }
done:
    if (out_len) *out_len = oi;
    return out;
}

uint8_t *apg_lz_decompress(const uint8_t *enc, uint32_t enc_len,
                             uint32_t max_out, uint32_t *out_len) {
    if (!enc || !enc_len) { if (out_len) *out_len = 0; return NULL; }
    size_t cap = max_out ? max_out : enc_len * 4;
    uint8_t *out = (uint8_t *)malloc(cap);
    if (!out) { if (out_len) *out_len = 0; return NULL; }
    uint32_t oi = 0, i = 0;
    while (i < enc_len) {
        uint8_t flags = enc[i++];
        for (int bit = 0; bit < 8 && i < enc_len; bit++) {
            if (flags & (1u << bit)) {
                /* back-reference */
                if (i + 2 >= enc_len) goto dec_done;
                uint16_t offset = (uint16_t)enc[i] | ((uint16_t)enc[i+1] << 8);
                uint8_t  mlen   = enc[i+2] + LZ_MIN_MATCH;
                i += 3;
                if (offset > oi) goto dec_done;
                for (uint8_t j = 0; j < mlen; j++) {
                    if (oi >= cap) { cap *= 2; uint8_t *p = (uint8_t*)realloc(out, cap); if (!p) goto dec_done; out = p; }
                    out[oi] = out[oi - offset];
                    oi++;
                }
            } else {
                if (oi >= cap) { cap *= 2; uint8_t *p = (uint8_t*)realloc(out, cap); if (!p) goto dec_done; out = p; }
                out[oi++] = enc[i++];
            }
        }
    }
dec_done:
    if (out_len) *out_len = oi;
    return out;
}

/* ---- byte frequency analysis (useful for choosing codec) ---- */

void apg_byte_frequency(const uint8_t *data, uint32_t len, uint32_t freq[256]) {
    memset(freq, 0, 256 * sizeof(uint32_t));
    for (uint32_t i = 0; i < len; i++) freq[data[i]]++;
}

uint32_t apg_unique_byte_count(const uint8_t *data, uint32_t len) {
    uint32_t freq[256];
    apg_byte_frequency(data, len, freq);
    uint32_t count = 0;
    for (int i = 0; i < 256; i++) if (freq[i]) count++;
    return count;
}

int apg_is_compressible(const uint8_t *data, uint32_t len) {
    if (!data || len < 64) return 0;
    uint32_t unique = apg_unique_byte_count(data, len);
    /* heuristic: fewer than 40% unique bytes suggests compressibility */
    return unique < (256 * 40 / 100);
}


/* ---- XOR masking (simple obfuscation, not encryption) ---- */

void apg_xor_mask(uint8_t *data, uint32_t len, uint32_t key) {
    uint8_t kb[4] = {
        (uint8_t)(key), (uint8_t)(key >> 8),
        (uint8_t)(key >> 16), (uint8_t)(key >> 24)
    };
    for (uint32_t i = 0; i < len; i++) data[i] ^= kb[i % 4];
}

/* ---- bit rotation ---- */

void apg_rotate_bits(uint8_t *data, uint32_t len, int shift) {
    shift = ((shift % 8) + 8) % 8;
    if (shift == 0) return;
    for (uint32_t i = 0; i < len; i++)
        data[i] = (uint8_t)((data[i] << shift) | (data[i] >> (8 - shift)));
}

/* ---- payload statistics for codec selection ---- */

typedef struct APG_CodecHint {
    int      use_rle;
    int      use_delta;
    int      use_lz;
    double   estimated_ratio;
} APG_CodecHint;

APG_CodecHint apg_codec_recommend(const uint8_t *data, uint32_t len) {
    APG_CodecHint h = {0, 0, 0, 1.0};
    if (!data || len < 32) return h;
    /* check run density */
    uint32_t runs = 0;
    for (uint32_t i = 1; i < len; i++) {
        if (data[i] == data[i-1]) runs++;
    }
    double run_ratio = (double)runs / (double)len;
    if (run_ratio > 0.3) { h.use_rle = 1; h.estimated_ratio = 1.0 - run_ratio * 0.5; }
    /* check monotonicity for delta */
    uint32_t monotone = 0;
    for (uint32_t i = 1; i < len; i++) {
        int diff = (int)data[i] - (int)data[i-1];
        if (diff >= -4 && diff <= 4) monotone++;
    }
    double mono_ratio = (double)monotone / (double)len;
    if (mono_ratio > 0.5) { h.use_delta = 1; h.estimated_ratio *= 0.7; }
    /* check unique byte count for LZ */
    uint32_t unique = apg_unique_byte_count(data, len);
    if (unique < 128 && len > 256) { h.use_lz = 1; h.estimated_ratio *= 0.6; }
    return h;
}
