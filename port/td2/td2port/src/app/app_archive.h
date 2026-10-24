#pragma once
/* Game files inside archives: zip, 7z, rar (4 and 5) and lha/lzh, read with libarchive. An archive is
 * unpacked once into a folder of the profile and used from there like any game folder (app_data.h). */
#include "../types.h"

/* Unpacks every regular file of `archive` into `dest`, keeping the archive's folders (paths that would
 * leave `dest` are skipped). Returns false with a message when the archive cannot be read. */
bool app_archive_unpack(const char *archive, const char *dest, char *err, size_t err_size);
