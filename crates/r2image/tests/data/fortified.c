/* One call to a fortified function whose interface is each C library's own.
 *
 * glibc's `__fgets_chk` takes the buffer's size second and the stream last;
 * bionic's takes the stream third and the buffer's size last. The same call
 * is built against each, and committed as bytes so the compiler on the
 * machine running the test cannot move the answer:
 *
 *   gcc -O1 -fno-stack-protector -Wl,--build-id=none \
 *       -o fortified_glibc.elf fortified.c
 *   gcc -O1 -fno-stack-protector -DBIONIC -nostartfiles -Wl,-e,main \
 *       -Wl,--dynamic-linker=/system/bin/linker64 -Wl,--build-id=none \
 *       -o fortified_bionic.elf fortified.c
 *
 * The second is what an Android program states of its platform -- bionic's
 * dynamic linker in `PT_INTERP`, and the identification note bionic's start
 * files leave -- with none of glibc's start files, so nothing in it names
 * glibc. It links against the build machine's libraries and never runs.
 */

#include <stddef.h>

typedef struct FILE FILE;
extern FILE *stdin;

#ifdef BIONIC
char *__fgets_chk(char *s, int n, FILE *stream, size_t size);
#define READ_LINE(buf, n) __fgets_chk((buf), (n), stdin, sizeof(buf))

/* bionic's `crtbegin` note: `Android`, type 1, the API level (here 30). */
__asm__(".pushsection .note.android.ident,\"a\",@note\n"
        ".balign 4\n"
        ".long 2f-1f\n"
        ".long 3f-2f\n"
        ".long 1\n"
        "1: .asciz \"Android\"\n"
        "2: .long 30\n"
        "3:\n"
        ".popsection\n");
#else
char *__fgets_chk(char *s, size_t size, int n, FILE *stream);
#define READ_LINE(buf, n) __fgets_chk((buf), sizeof(buf), (n), stdin)
#endif

int first_char(void) {
    char line[64];
    if (!READ_LINE(line, 32))
        return -1;
    return line[0];
}

int main(void) { return first_char(); }
