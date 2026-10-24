/* app_archive.h with libarchive. */
#include "app_archive.h"

#include <SDL3/SDL.h>
#include <archive.h>
#include <archive_entry.h>

/* A relative path inside the archive, with '\' as '/', and no empty, "." or ".." parts; NULL if it
 * would leave the destination. The result is SDL_malloc'd. */
static char *safe_path(const char *name)
{
    if (!name || !*name || name[0] == '/' || name[0] == '\\' || SDL_strchr(name, ':')) return NULL;
    char *out = SDL_malloc(SDL_strlen(name) + 1);
    if (!out) return NULL;
    size_t n = 0;
    for (const char *p = name; *p; ) {
        const char *end = p;
        while (*end && *end != '/' && *end != '\\') end++;
        size_t len = (size_t)(end - p);
        if (len == 2 && p[0] == '.' && p[1] == '.') {
            SDL_free(out);
            return NULL;
        }
        if (len && !(len == 1 && p[0] == '.')) {
            if (n) out[n++] = '/';
            SDL_memcpy(out + n, p, len);
            n += len;
        }
        p = *end ? end + 1 : end;
    }
    out[n] = 0;
    if (!n) {
        SDL_free(out);
        return NULL;
    }
    return out;
}

static bool make_parents(const char *path)
{
    char *dir = SDL_strdup(path);
    char *slash = SDL_strrchr(dir, '/');
    bool ok = true;
    if (slash) {
        *slash = 0;
        ok = SDL_CreateDirectory(dir);
    }
    SDL_free(dir);
    return ok;
}

bool app_archive_unpack(const char *archive, const char *dest, char *err, size_t err_size)
{
    struct archive *a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_zip(a);
    archive_read_support_format_7zip(a);
    archive_read_support_format_rar(a);
    archive_read_support_format_rar5(a);
    archive_read_support_format_lha(a);
    int r;
#ifdef _WIN32
    wchar_t *wide = (wchar_t *)SDL_iconv_string("UTF-16LE", "UTF-8", archive, SDL_strlen(archive) + 1);
    r = wide ? archive_read_open_filename_w(a, wide, 64 * 1024) : ARCHIVE_FATAL;
    SDL_free(wide);
#else
    r = archive_read_open_filename(a, archive, 64 * 1024);
#endif
    if (r != ARCHIVE_OK) {
        SDL_snprintf(err, err_size, "Cannot open the archive %s: %s", archive, archive_error_string(a));
        archive_read_free(a);
        return false;
    }
    bool ok = SDL_CreateDirectory(dest);
    struct archive_entry *e;
    char buf[64 * 1024];
    while (ok && (r = archive_read_next_header(a, &e)) == ARCHIVE_OK) {
        if (archive_entry_filetype(e) != AE_IFREG) continue;
        const char *name = archive_entry_pathname_utf8(e);
        char *rel = safe_path(name ? name : archive_entry_pathname(e));
        if (!rel) continue;
        char *path = NULL;
        SDL_asprintf(&path, "%s/%s", dest, rel);
        SDL_free(rel);
        SDL_IOStream *out = make_parents(path) ? SDL_IOFromFile(path, "wb") : NULL;
        if (!out) {
            SDL_snprintf(err, err_size, "Cannot write %s: %s", path, SDL_GetError());
            ok = false;
        }
        for (la_ssize_t n; ok && (n = archive_read_data(a, buf, sizeof buf)) != 0; ) {
            if (n < 0) {
                SDL_snprintf(err, err_size, "Cannot unpack %s from %s: %s", path, archive, archive_error_string(a));
                ok = false;
            } else if (SDL_WriteIO(out, buf, (size_t)n) != (size_t)n) {
                SDL_snprintf(err, err_size, "Cannot write %s: %s", path, SDL_GetError());
                ok = false;
            }
        }
        if (out && !SDL_CloseIO(out)) ok = false;
        SDL_free(path);
    }
    if (ok && r != ARCHIVE_EOF) {
        SDL_snprintf(err, err_size, "Cannot read the archive %s: %s", archive, archive_error_string(a));
        ok = false;
    }
    archive_read_free(a);
    return ok;
}
