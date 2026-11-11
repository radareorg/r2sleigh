/*
 * The Win64 target's image loader: a PE32+ mapped at its own ImageBase inside the Linux runtime.
 *
 * The gate grades a Win64 function the way it grades an ELF one: in one Linux process, through
 * fork. This file maps the original PE where its link placed it (so no relocation applies and
 * an address the rendering spells is the image's), binds each import to a Microsoft x64 shim
 * over glibc, and names the image's writable sections as the segments a run compares. An
 * import with no shim binds to equiv_unbound, which aborts: the original then lies outside the
 * vector's domain and no rendering is asked. Included by equiv_rt.c under EQUIV_WIN64.
 */
#include <ctype.h>
#include <math.h>
#include <stdarg.h>

#define MS __attribute__((ms_abi))

/* The image's names and the shims they bind to, in strcmp order (bsearch). */
struct shim {
    const char *name;
    void *fn;
};

static char g_unbound[2048];
static size_t g_unbound_len;

MS static void equiv_unbound(void)
{
    abort();
}

/* A Microsoft x64 `va_list` is a pointer to 8-byte argument slots: a System V one whose
 * register area is spent reads the same slots from its overflow area. */
#define SYSV_LIST(name, slots)                                                                  \
    va_list name;                                                                               \
    name[0].gp_offset = 48;                                                                     \
    name[0].fp_offset = 176;                                                                    \
    name[0].overflow_arg_area = (void *)(slots);                                                \
    name[0].reg_save_area = NULL

MS static FILE *ms_acrt_iob_func(unsigned index)
{
    return index == 0 ? stdin : index == 1 ? stdout : index == 2 ? stderr : NULL;
}

MS static int ms_stdio_common_vfprintf(uint64_t options, FILE *stream, const char *format,
                                       void *locale, char *slots)
{
    (void)options;
    (void)locale;
    SYSV_LIST(list, slots);
    return vfprintf(stream, format, list);
}

/* UCRT's sprintf family: a count of 0 with no buffer asks for the length; the legacy bit
 * (_CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR clear) returns -1 on truncation. */
MS static int ms_stdio_common_vsprintf(uint64_t options, char *buffer, size_t count,
                                       const char *format, void *locale, char *slots)
{
    (void)locale;
    SYSV_LIST(list, slots);
    int written = vsnprintf(buffer, count, format, list);
    if (!(options & 2) && buffer && written >= 0 && (size_t)written >= count)
        return -1;
    return written;
}

MS static int ms_stdio_common_vsscanf(uint64_t options, const char *input, size_t length,
                                      const char *format, void *locale, char *slots)
{
    (void)options;
    (void)length;
    (void)locale;
    SYSV_LIST(list, slots);
    return vsscanf(input, format, list);
}

MS static int *ms_errno(void) { return &errno; }
MS static void *ms_malloc(size_t n) { return malloc(n); }
MS static void *ms_calloc(size_t n, size_t size) { return calloc(n, size); }
MS static void *ms_realloc(void *p, size_t n) { return realloc(p, n); }
MS static void ms_free(void *p) { free(p); }
MS static void *ms_memcpy(void *d, const void *s, size_t n) { return memcpy(d, s, n); }
MS static void *ms_memmove(void *d, const void *s, size_t n) { return memmove(d, s, n); }
MS static void *ms_memset(void *d, int c, size_t n) { return memset(d, c, n); }
MS static int ms_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
MS static void *ms_memchr(const void *s, int c, size_t n) { return memchr(s, c, n); }
MS static size_t ms_strlen(const char *s) { return strlen(s); }
MS static size_t ms_strnlen(const char *s, size_t n) { return strnlen(s, n); }
MS static int ms_strcmp(const char *a, const char *b) { return strcmp(a, b); }
MS static int ms_strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); }
MS static char *ms_strcpy(char *d, const char *s) { return strcpy(d, s); }
MS static char *ms_strncpy(char *d, const char *s, size_t n) { return strncpy(d, s, n); }
MS static char *ms_strcat(char *d, const char *s) { return strcat(d, s); }
MS static char *ms_strncat(char *d, const char *s, size_t n) { return strncat(d, s, n); }
MS static char *ms_strchr(const char *s, int c) { return strchr(s, c); }
MS static char *ms_strrchr(const char *s, int c) { return strrchr(s, c); }
MS static char *ms_strstr(const char *h, const char *n) { return strstr(h, n); }
MS static char *ms_strdup(const char *s) { return strdup(s); }
MS static size_t ms_strspn(const char *s, const char *a) { return strspn(s, a); }
MS static size_t ms_strcspn(const char *s, const char *a) { return strcspn(s, a); }
MS static char *ms_strpbrk(const char *s, const char *a) { return strpbrk(s, a); }
MS static char *ms_strtok(char *s, const char *d) { return strtok(s, d); }
MS static int ms_atoi(const char *s) { return atoi(s); }
MS static int ms_abs(int v) { return abs(v); }
MS static long long ms_llabs(long long v) { return llabs(v); }
MS static long long ms_strtoll(const char *s, char **e, int b) { return strtoll(s, e, b); }
MS static unsigned long long ms_strtoull(const char *s, char **e, int b) { return strtoull(s, e, b); }
MS static double ms_strtod(const char *s, char **e) { return strtod(s, e); }
MS static double ms_atof(const char *s) { return atof(s); }

/* LLP64: long is 32 bits, so strtol clamps where Microsoft's does. */
MS static int32_t ms_strtol(const char *s, char **e, int b)
{
    long long v = strtoll(s, e, b);
    if (v > INT32_MAX) {
        errno = ERANGE;
        return INT32_MAX;
    }
    if (v < INT32_MIN) {
        errno = ERANGE;
        return INT32_MIN;
    }
    return (int32_t)v;
}

MS static uint32_t ms_strtoul(const char *s, char **e, int b)
{
    unsigned long long v = strtoull(s, e, b);
    if (v > UINT32_MAX && v < (unsigned long long)INT64_MIN) {
        errno = ERANGE;
        return UINT32_MAX;
    }
    return (uint32_t)v;
}

MS static int32_t ms_atol(const char *s) { return (int32_t)atol(s); }
MS static int32_t ms_labs(int32_t v) { return v < 0 ? -v : v; }
MS static int ms_toupper(int c) { return toupper(c); }
MS static int ms_tolower(int c) { return tolower(c); }
MS static int ms_isdigit(int c) { return isdigit(c); }
MS static int ms_isalpha(int c) { return isalpha(c); }
MS static int ms_isalnum(int c) { return isalnum(c); }
MS static int ms_isspace(int c) { return isspace(c); }
MS static int ms_isupper(int c) { return isupper(c); }
MS static int ms_islower(int c) { return islower(c); }
MS static int ms_isxdigit(int c) { return isxdigit(c); }
MS static int ms_isprint(int c) { return isprint(c); }
MS static int ms_ispunct(int c) { return ispunct(c); }
MS static int ms_puts(const char *s) { return puts(s); }
MS static int ms_putchar(int c) { return putchar(c); }
MS static int ms_fputs(const char *s, FILE *f) { return fputs(s, f); }
MS static int ms_fputc(int c, FILE *f) { return fputc(c, f); }
MS static size_t ms_fwrite(const void *p, size_t s, size_t n, FILE *f) { return fwrite(p, s, n, f); }
MS static int ms_fflush(FILE *f) { return fflush(f); }
MS static void ms_exit(int status) { exit(status); }
MS static void ms_quick_exit(int status) { _exit(status); }
MS static void ms_abort(void) { abort(); }
MS static double ms_sqrt(double x) { return sqrt(x); }
MS static double ms_sin(double x) { return sin(x); }
MS static double ms_cos(double x) { return cos(x); }
MS static double ms_tan(double x) { return tan(x); }
MS static double ms_atan(double x) { return atan(x); }
MS static double ms_atan2(double y, double x) { return atan2(y, x); }
MS static double ms_exp(double x) { return exp(x); }
MS static double ms_log(double x) { return log(x); }
MS static double ms_log10(double x) { return log10(x); }
MS static double ms_pow(double x, double y) { return pow(x, y); }
MS static double ms_floor(double x) { return floor(x); }
MS static double ms_ceil(double x) { return ceil(x); }
MS static double ms_fmod(double x, double y) { return fmod(x, y); }
MS static double ms_fabs(double x) { return fabs(x); }
MS static double ms_round(double x) { return round(x); }
MS static double ms_trunc(double x) { return trunc(x); }
MS static float ms_sqrtf(float x) { return sqrtf(x); }
MS static float ms_floorf(float x) { return floorf(x); }
MS static float ms_ceilf(float x) { return ceilf(x); }
MS static float ms_fmodf(float x, float y) { return fmodf(x, y); }

/* qsort and bsearch call back into the image with Microsoft's convention; one call at a time. */
typedef int (MS *ms_compare)(const void *, const void *);
static ms_compare g_compare;

static int sysv_compare(const void *a, const void *b)
{
    return g_compare(a, b);
}

MS static void ms_qsort(void *base, size_t n, size_t size, ms_compare compare)
{
    ms_compare outer = g_compare;
    g_compare = compare;
    qsort(base, n, size, sysv_compare);
    g_compare = outer;
}

MS static void *ms_bsearch(const void *key, const void *base, size_t n, size_t size,
                           ms_compare compare)
{
    ms_compare outer = g_compare;
    g_compare = compare;
    void *found = bsearch(key, base, n, size, sysv_compare);
    g_compare = outer;
    return found;
}

static const struct shim g_shims[] = {
    { "__acrt_iob_func", (void *)ms_acrt_iob_func },
    { "__stdio_common_vfprintf", (void *)ms_stdio_common_vfprintf },
    { "__stdio_common_vsprintf", (void *)ms_stdio_common_vsprintf },
    { "__stdio_common_vsscanf", (void *)ms_stdio_common_vsscanf },
    { "_errno", (void *)ms_errno },
    { "_exit", (void *)ms_quick_exit },
    { "_strdup", (void *)ms_strdup },
    { "abort", (void *)ms_abort },
    { "abs", (void *)ms_abs },
    { "atan", (void *)ms_atan },
    { "atan2", (void *)ms_atan2 },
    { "atof", (void *)ms_atof },
    { "atoi", (void *)ms_atoi },
    { "atol", (void *)ms_atol },
    { "bsearch", (void *)ms_bsearch },
    { "calloc", (void *)ms_calloc },
    { "ceil", (void *)ms_ceil },
    { "ceilf", (void *)ms_ceilf },
    { "cos", (void *)ms_cos },
    { "exit", (void *)ms_exit },
    { "exp", (void *)ms_exp },
    { "fabs", (void *)ms_fabs },
    { "fflush", (void *)ms_fflush },
    { "floor", (void *)ms_floor },
    { "floorf", (void *)ms_floorf },
    { "fmod", (void *)ms_fmod },
    { "fmodf", (void *)ms_fmodf },
    { "fputc", (void *)ms_fputc },
    { "fputs", (void *)ms_fputs },
    { "free", (void *)ms_free },
    { "fwrite", (void *)ms_fwrite },
    { "isalnum", (void *)ms_isalnum },
    { "isalpha", (void *)ms_isalpha },
    { "isdigit", (void *)ms_isdigit },
    { "islower", (void *)ms_islower },
    { "isprint", (void *)ms_isprint },
    { "ispunct", (void *)ms_ispunct },
    { "isspace", (void *)ms_isspace },
    { "isupper", (void *)ms_isupper },
    { "isxdigit", (void *)ms_isxdigit },
    { "labs", (void *)ms_labs },
    { "llabs", (void *)ms_llabs },
    { "log", (void *)ms_log },
    { "log10", (void *)ms_log10 },
    { "malloc", (void *)ms_malloc },
    { "memchr", (void *)ms_memchr },
    { "memcmp", (void *)ms_memcmp },
    { "memcpy", (void *)ms_memcpy },
    { "memmove", (void *)ms_memmove },
    { "memset", (void *)ms_memset },
    { "pow", (void *)ms_pow },
    { "putchar", (void *)ms_putchar },
    { "puts", (void *)ms_puts },
    { "qsort", (void *)ms_qsort },
    { "quick_exit", (void *)ms_quick_exit },
    { "realloc", (void *)ms_realloc },
    { "round", (void *)ms_round },
    { "sin", (void *)ms_sin },
    { "sqrt", (void *)ms_sqrt },
    { "sqrtf", (void *)ms_sqrtf },
    { "strcat", (void *)ms_strcat },
    { "strchr", (void *)ms_strchr },
    { "strcmp", (void *)ms_strcmp },
    { "strcpy", (void *)ms_strcpy },
    { "strcspn", (void *)ms_strcspn },
    { "strlen", (void *)ms_strlen },
    { "strncat", (void *)ms_strncat },
    { "strncmp", (void *)ms_strncmp },
    { "strncpy", (void *)ms_strncpy },
    { "strnlen", (void *)ms_strnlen },
    { "strpbrk", (void *)ms_strpbrk },
    { "strrchr", (void *)ms_strrchr },
    { "strspn", (void *)ms_strspn },
    { "strstr", (void *)ms_strstr },
    { "strtod", (void *)ms_strtod },
    { "strtok", (void *)ms_strtok },
    { "strtol", (void *)ms_strtol },
    { "strtoll", (void *)ms_strtoll },
    { "strtoul", (void *)ms_strtoul },
    { "strtoull", (void *)ms_strtoull },
    { "tan", (void *)ms_tan },
    { "tolower", (void *)ms_tolower },
    { "toupper", (void *)ms_toupper },
    { "trunc", (void *)ms_trunc },
};

static int shim_order(const void *key, const void *entry)
{
    return strcmp((const char *)key, ((const struct shim *)entry)->name);
}

/* The shim an import binds to, or equiv_unbound, whose name is then kept for the header. */
static void *pe_bind(const char *name)
{
    const struct shim *found = bsearch(name, g_shims, sizeof g_shims / sizeof g_shims[0],
                                       sizeof g_shims[0], shim_order);
    if (found)
        return found->fn;
    size_t length = strlen(name);
    if (g_unbound_len + length + 2 < sizeof g_unbound) {
        if (g_unbound_len)
            g_unbound[g_unbound_len++] = ' ';
        memcpy(g_unbound + g_unbound_len, name, length);
        g_unbound_len += length;
        g_unbound[g_unbound_len] = '\0';
    }
    return (void *)equiv_unbound;
}

static uint16_t rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

#define SCN_EXECUTE 0x20000000u
#define SCN_READ 0x40000000u
#define SCN_WRITE 0x80000000u

/* Map `path` at its ImageBase, bind its imports and record its writable sections; a message
 * on failure. Every read is bounded by the file and by SizeOfImage. */
static const char *pe_load(const char *path)
{
    size_t length = 0;
    uint8_t *file = read_file(path, &length);
    if (!file || length < 0x40 || file[0] != 'M' || file[1] != 'Z')
        return "EQUIV_PE is no PE file";
    uint32_t pe = rd32(file + 0x3c);
    if (pe > length - 24 || memcmp(file + pe, "PE\0\0", 4) != 0 || rd16(file + pe + 4) != 0x8664)
        return "EQUIV_PE is no x86-64 PE image";
    uint16_t sections = rd16(file + pe + 6);
    uint16_t optional_size = rd16(file + pe + 20);
    const uint8_t *opt = file + pe + 24;
    if ((size_t)(opt - file) + optional_size > length || optional_size < 112 + 16 * 8
        || rd16(opt) != 0x20b)
        return "EQUIV_PE has no PE32+ optional header";
    uint64_t base = rd64(opt + 24);
    uint32_t image_size = rd32(opt + 56);
    uint32_t header_size = rd32(opt + 60);
    const uint8_t *directories = opt + 112;
    const uint8_t *table = opt + optional_size;
    if ((size_t)(table - file) + (size_t)sections * 40 > length || header_size > length
        || header_size > image_size)
        return "EQUIV_PE's section table lies outside the file";
    uint8_t *image = mmap((void *)(uintptr_t)base, image_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (image == MAP_FAILED || (uint64_t)(uintptr_t)image != base)
        return "cannot map the PE at its ImageBase";
    memcpy(image, file, header_size);
    for (uint16_t i = 0; i < sections; i++) {
        const uint8_t *s = table + i * 40;
        uint32_t vsize = rd32(s + 8), rva = rd32(s + 12), raw = rd32(s + 16), at = rd32(s + 20);
        uint32_t copy = raw < vsize ? raw : vsize;
        if (rva > image_size || copy > image_size - rva || at > length || copy > length - at)
            return "a PE section lies outside the image or the file";
        memcpy(image + rva, file + at, copy);
    }
    uint32_t imports = rd32(directories + 8), imports_size = rd32(directories + 12);
    for (uint32_t at = imports; imports_size && at + 20 <= image_size; at += 20) {
        const uint8_t *d = image + at;
        uint32_t names = rd32(d), name = rd32(d + 12), slots = rd32(d + 16);
        if (!name && !slots)
            break;
        if (!names)
            names = slots;
        for (uint32_t k = 0;; k++) {
            if (names + 8 * k + 8 > image_size || slots + 8 * k + 8 > image_size)
                return "a PE import table lies outside the image";
            uint64_t entry = rd64(image + names + 8 * k);
            if (!entry)
                break;
            void *fn = (void *)equiv_unbound;
            if (!(entry >> 63) && entry + 2 < image_size)
                fn = pe_bind((const char *)image + entry + 2);
            memcpy(image + slots + 8 * k, &fn, 8);
        }
    }
    if (mprotect(image, header_size, PROT_READ) != 0)
        return "cannot protect the PE headers";
    for (uint16_t i = 0; i < sections; i++) {
        const uint8_t *s = table + i * 40;
        uint32_t vsize = rd32(s + 8), rva = rd32(s + 12), flags = rd32(s + 36);
        int prot = (flags & SCN_READ ? PROT_READ : 0) | (flags & SCN_WRITE ? PROT_WRITE : 0)
            | (flags & SCN_EXECUTE ? PROT_EXEC : 0);
        uintptr_t page = (uintptr_t)sysconf(_SC_PAGESIZE);
        uintptr_t low = (uintptr_t)(image + rva) & ~(page - 1);
        uintptr_t high = ((uintptr_t)(image + rva + vsize) + page - 1) & ~(page - 1);
        if (mprotect((void *)low, high - low, prot) != 0)
            return "cannot protect a PE section";
        if (!(flags & SCN_WRITE) || vsize == 0)
            continue;
        if (g_n_segments == sizeof g_segments / sizeof g_segments[0])
            return "the PE has more writable sections than the runtime keeps";
        g_segments[g_n_segments].start = base + rva;
        g_segments[g_n_segments].length = vsize;
        g_segment_bytes += vsize;
        g_n_segments++;
    }
    free(file);
    return NULL;
}
