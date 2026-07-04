
#include "internal.h"

void apg_context_init(APG_Context *ctx) {
    if (!ctx) return;
    ctx->error_code = APG_ERR_NONE;
    ctx->fatal = 0;
    ctx->message[0] = '\0';
}

void apg_set_error(APG_Context *ctx, int code, const char *msg) {
    if (!ctx) return;
    if (ctx->error_code == APG_ERR_NONE) {
        ctx->error_code = code;
        if (msg) {
            snprintf(ctx->message, sizeof(ctx->message), "%s", msg);
        }
    }
}

void apg_set_fatal(APG_Context *ctx, int code, const char *msg) {
    if (!ctx) return;
    ctx->fatal = 1;
    ctx->error_code = code;
    if (msg) snprintf(ctx->message, sizeof(ctx->message), "%s", msg);
}

int apg_has_fatal(const APG_Context *ctx) {
    return ctx && ctx->fatal;
}


/* ---- context error reporting ---- */

const char *apg_error_string(int error_code) {
    switch (error_code) {
        case 0: return "no error";
        case 1: return "invalid magic";
        case 2: return "unsupported version";
        case 3: return "truncated input";
        case 4: return "invalid directory";
        case 5: return "section overflow";
        case 6: return "allocation failure";
        default: return "unknown error";
    }
}

int apg_context_has_error(const APG_Context *ctx) {
    return ctx && ctx->error_code != 0;
}

int apg_context_is_fatal(const APG_Context *ctx) {
    return ctx && ctx->fatal;
}
