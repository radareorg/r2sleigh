/*
 * equiv_rt: the in-image runtime of the compile-and-diff equivalence gate.
 *
 * Loaded with LD_PRELOAD into the ORIGINAL binary. It interposes
 * __libc_start_main, so the dynamic linker, libc and the program's own
 * constructors have all run, and then runs a job instead of main:
 *
 *   for every vector:
 *     the arena (a fixed-address mapping every pointer argument points into)
 *     is filled from the vector's seed and patched with its objects;
 *     for every run (the original at its link address, then each rendering
 *     loaded from its shared object), one child is forked from that same
 *     parent state and calls its function through the register-level thunk
 *     (call_x86_64.S, call_aarch64.S) with the vector's machine entry state;
 *     in a rendering's child the rendering first REPLACES the graded function
 *     in the image: every instruction of the original's code becomes a trap
 *     (int3 on x86-64, brk on AArch64), a call
 *     into its entry from the program (a caller of the function, a function
 *     pointer, a mutual recursion) is redirected to the rendering, and control
 *     that reaches the original's code from the rendering itself (delegation)
 *     or anywhere inside its body ends the run, so a rendering is only ever
 *     graded on what its own code does;
 *     each child records how it ended, its return registers, the arena, the
 *     program's writable PT_LOAD bytes, and what it wrote to fd 1 and fd 2 --
 *     a rendering that traps in its own code, at the trap, with its site;
 *     the parent compares the requested pairs of runs and writes one JSON
 *     line per vector to $EQUIV_OUT.
 *
 * Nothing is compared inside a child and the parent never calls a function
 * under test, so a crash, a hang or a stray write is one run's evidence and
 * never the harness's state. Without $EQUIV_JOB the interposer is inert and
 * the program's own main runs.
 *
 * Job file (little-endian, all offsets 8-byte aligned):
 *   struct job_header
 *   struct job_run      [n_runs]
 *   struct job_pair     [n_pairs]
 *   n_vectors x { struct job_vector, n_patches x { struct job_patch, bytes
 *                 padded to 8 } }
 *
 * Everything that depends on the machine -- the entry state the thunk loads,
 * where a signal context keeps the program counter and the caller's return
 * address, and the trap that fills the guarded code -- is in the one block
 * below; the rest of the runtime is the same on every target.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <link.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/* ------------------------------------------------------------- machine */

#if defined(__x86_64__)

/* SysV x86-64: rdi..r9, xmm0..xmm7, AL, then stack words (call_x86_64.S). */
struct equiv_regs {
    uint64_t gpr[6];
    uint8_t xmm[8][16];
    uint64_t rax;
    uint64_t n_stack;
    uint64_t stack[16];
};

#define RET_INT_NAME "rax"
#define RET_FP_NAME "xmm0"
/* What __builtin_trap raises: ud2. */
#define TRAP_SIGNAL SIGILL

static uint64_t context_pc(const ucontext_t *uc)
{
    return (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
}

static void context_set_pc(ucontext_t *uc, uint64_t pc)
{
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)pc;
}

static uint64_t context_sp(const ucontext_t *uc)
{
    return (uint64_t)uc->uc_mcontext.gregs[REG_RSP];
}

/* The first integer argument register. */
static uint64_t context_arg0(const ucontext_t *uc)
{
    return (uint64_t)uc->uc_mcontext.gregs[REG_RDI];
}

/* int3 reports the byte after it. */
static uint64_t trap_address(const ucontext_t *uc)
{
    return context_pc(uc) - 1;
}

/* At a function's entry the return address is the word at the stack pointer. */
static uint64_t entry_return_address(const ucontext_t *uc)
{
    return *(const uint64_t *)(uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
}

/* Where the direct call ending just before `ret` went, or 0 where that is no
 * `call rel32` (an indirect call states no target here). */
static uint64_t direct_call_target(uint64_t ret)
{
    const uint8_t *call = (const uint8_t *)(uintptr_t)(ret - 5);
    if (call[0] != 0xe8)
        return 0;
    int32_t rel;
    memcpy(&rel, call + 1, sizeof rel);
    return ret + (uint64_t)(int64_t)rel;
}

/* int3 over every byte: any byte control can reach traps. */
static void trap_fill(uint8_t *start, size_t length)
{
    memset(start, 0xcc, length);
}

#elif defined(__aarch64__)

/* AAPCS64: x0..x7, v0..v7, then stack words (call_aarch64.S). */
struct equiv_regs {
    uint64_t gpr[8];
    uint8_t v[8][16];
    uint64_t n_stack;
    uint64_t stack[16];
};

#define RET_INT_NAME "x0"
#define RET_FP_NAME "v0"
/* What __builtin_trap raises: brk. */
#define TRAP_SIGNAL SIGTRAP

static uint64_t context_pc(const ucontext_t *uc)
{
    return (uint64_t)uc->uc_mcontext.pc;
}

static void context_set_pc(ucontext_t *uc, uint64_t pc)
{
    uc->uc_mcontext.pc = pc;
}

static uint64_t context_sp(const ucontext_t *uc)
{
    return (uint64_t)uc->uc_mcontext.sp;
}

/* The first integer argument register. */
static uint64_t context_arg0(const ucontext_t *uc)
{
    return (uint64_t)uc->uc_mcontext.regs[0];
}

/* brk reports its own address. */
static uint64_t trap_address(const ucontext_t *uc)
{
    return context_pc(uc);
}

/* At a function's entry the return address is the link register, x30. */
static uint64_t entry_return_address(const ucontext_t *uc)
{
    return (uint64_t)uc->uc_mcontext.regs[30];
}

/* Where the `bl` just before `ret` went, or 0 where that is no `bl` (a `blr`
 * states no target here). */
static uint64_t direct_call_target(uint64_t ret)
{
    uint32_t word;
    memcpy(&word, (const void *)(uintptr_t)(ret - 4), sizeof word);
    if ((word & 0xfc000000u) != 0x94000000u)
        return 0;
    int64_t imm = (int64_t)((word & 0x03ffffffu) << 6) >> 4;
    return ret - 4 + (uint64_t)imm;
}

/* brk #0 over every instruction word: instructions are 4-byte aligned, so any
 * instruction control can reach traps. A tail shorter than a word (a symbol
 * size that is not a multiple of four) holds no instruction. */
static void trap_fill(uint8_t *start, size_t length)
{
    const uint32_t brk = 0xd4200000u;
    for (size_t at = 0; at + 4 <= length; at += 4)
        memcpy(start + at, &brk, 4);
}

#else
#error "equiv_rt models x86-64 and AArch64 only"
#endif

/* vectors.py packs struct equiv_regs from target.Abi.regs_format(), and
 * test_equiv.py holds the job's vectors to these sizes. */
#if defined(__x86_64__)
_Static_assert(sizeof(struct equiv_regs) == 320, "the x86-64 job layout");
#else
_Static_assert(sizeof(struct equiv_regs) == 328, "the AArch64 job layout");
#endif

/* The first two integer result registers (rax rdx, x0 x1) and the first two
 * vector result registers (xmm0 xmm1, v0 v1), as the thunk stores them. */
struct equiv_ret {
    uint64_t r0;
    uint64_t r1;
    uint8_t f0[16];
    uint8_t f1[16];
};

extern void equiv_call(void *fn, const struct equiv_regs *in, struct equiv_ret *out);

#define JOB_MAGIC "EQVJOB03"

enum ret_kind { RET_VOID = 0, RET_INT = 1, RET_F32 = 2, RET_F64 = 3, RET_INT128 = 4 };

struct job_header {
    char magic[8];
    uint64_t arena_base;
    uint64_t arena_size;
    uint64_t guard_start;     /* the graded function's code in the image: */
    uint64_t guard_length;    /* [guard_start, guard_start + guard_length) */
    uint32_t n_runs;
    uint32_t n_vectors;
    uint32_t n_pairs;
    uint32_t hang_ms;         /* wall-clock guard per run when the budget counts instructions */
    uint32_t ret_kind;
    uint32_t ret_bytes;
    uint32_t out_cap;         /* bytes of fd 1 and of fd 2 kept per run */
    uint32_t measure;         /* MEASURE_*: what budget counts */
    uint64_t budget;          /* the original's, in ms or instructions; renderings get four times it */
    uint64_t fake_count;      /* tests: what each rendering run counts in place of the counter */
};

/* doc/adr-verified-layers.md D38. */
enum measure { MEASURE_TIME = 0, MEASURE_INSTRUCTIONS = 1 };
_Static_assert(sizeof(struct job_header) == 88, "the job header layout (vectors.encode_job)");

struct job_run {
    uint64_t address;         /* called directly when so_path is empty */
    uint32_t replaces;        /* 1: this run's function replaces the graded one */
    uint32_t reserved;
    char so_path[512];
    char symbol[256];
    char label[32];
};

struct job_pair {
    uint32_t a;
    uint32_t b;
};

struct job_vector {
    uint64_t seed;
    struct equiv_regs regs;
    uint32_t n_patches;
    uint32_t reserved;
};

struct job_patch {
    uint64_t offset;
    uint64_t length;
};

/* How a run ended. */
enum outcome {
    OUT_UNAVAILABLE = 0,      /* its function could not be loaded */
    OUT_RETURN = 1,           /* returned; everything captured */
    OUT_EXIT = 2,             /* called exit(); captured from the atexit hook */
    OUT_EXIT_RAW = 3,         /* ended with a status and no capture (_exit, a sanitizer) */
    OUT_SIGNAL = 4,
    OUT_BUDGET = 5,           /* stopped past its budget: the only outcome that is `slow` */
    OUT_SKIPPED = 6,          /* not run: the original was outside its domain */
    OUT_HANG = 7              /* stopped by the wall-clock guard, which says nothing of cost */
};

static const char *outcome_name[] = {
    "unavailable", "return", "exit", "exit-raw", "signal", "budget", "skipped", "hang",
};

/* What a child leaves in shared memory. The arena and segment bytes follow. */
struct slot_head {
    volatile int32_t captured;   /* 1 = return, 2 = exit hook */
    int32_t fault_signal;
    uint64_t fault_pc;
    uint64_t fault_addr;
    int32_t fault_on_stack;      /* the fault address lies at the stack pointer: stack exhausted */
    uint64_t fault_base;         /* load base of fault_object, to read its symbols */
    char fault_object[256];
    int32_t guard;               /* GUARD_*: how control reached the original's code */
    int32_t guard_error;         /* errno of a guard that could not be installed */
    uint64_t guard_caller;       /* return address at a delegated entry */
    uint64_t insns;              /* instructions the call retired, where counted */
    int32_t counter_error;       /* errno of a counter that could not be armed */
    uint32_t trap_site;          /* arg 0 at a trap in the rendering: a residual's site */
    int32_t trap_depth;          /* TRAP_*: which activation of the function trapped */
    uint64_t out_at_capture;     /* bytes on fd 1 and fd 2 when the state was captured */
    uint64_t err_at_capture;
    struct equiv_ret ret;
};

/* captured: what a child's state was snapshotted at. */
enum capture { CAPTURE_NONE = 0, CAPTURE_RETURN = 1, CAPTURE_EXIT = 2, CAPTURE_TRAP = 3 };
enum trap_depth { TRAP_UNKNOWN = 0, TRAP_OUTERMOST = 1, TRAP_NESTED = 2 };
static const char *trap_depth_name[] = { "unknown", "outermost", "nested" };

enum guard_hit { GUARD_NONE = 0, GUARD_DELEGATED = 1, GUARD_BODY = 2 };
static const char *guard_name[] = { "none", "delegated", "body" };

struct segment {
    uint64_t start;
    uint64_t length;
};

struct run_state {
    const struct job_run *spec;
    void *fn;
    void *handle;
    char load_error[512];
    struct slot_head *slot;      /* followed by arena bytes, then segment bytes */
    size_t slot_size;
    int out_fd;
    int err_fd;
    /* Filled per vector by the parent. */
    int outcome;
    int status;
    size_t out_len;
    size_t err_len;
    char *out_buf;
    char *err_buf;
};

static struct job_header g_head;
static struct run_state *g_runs;
static struct segment g_segments[16];
static size_t g_n_segments;
static size_t g_segment_bytes;
static uint8_t *g_arena;

/* Child-side state for the exit hook and the fault handler. */
static struct slot_head *g_child_slot;
static volatile int g_in_call;
/* A rendering's child: its function, that function's extent, and the runtime's base. */
static uintptr_t g_child_fn;
static size_t g_child_fn_size;
static uintptr_t g_child_own_base;
static uintptr_t g_rt_base;
/* Child-side state for the guard: where a redirected entry goes, and the
 * objects whose code may not enter the original (the rendering, this runtime). */
static void *g_guard_target;
static uintptr_t g_guard_own_base;
static uintptr_t g_guard_rt_base;

static FILE *g_out;

/* ---------------------------------------------------------------- helpers */

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

static void json_string(FILE *out, const char *text, size_t length)
{
    fputc('"', out);
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)text[i];
        switch (c) {
        case '"': fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n", out); break;
        case '\r': fputs("\\r", out); break;
        case '\t': fputs("\\t", out); break;
        default:
            if (c < 0x20 || c >= 0x7f)
                fprintf(out, "\\u%04x", c);
            else
                fputc(c, out);
        }
    }
    fputc('"', out);
}

static void json_hex(FILE *out, const uint8_t *bytes, size_t length)
{
    fputc('"', out);
    for (size_t i = 0; i < length; i++)
        fprintf(out, "%02x", bytes[i]);
    fputc('"', out);
}

static int die(const char *what)
{
    if (g_out) {
        fputs("{\"error\":", g_out);
        json_string(g_out, what, strlen(what));
        fputs("}\n", g_out);
        fflush(g_out);
    }
    fprintf(stderr, "equiv_rt: %s\n", what);
    return 70;
}

static void *read_file(const char *path, size_t *length)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return NULL;
    }
    uint8_t *buffer = malloc((size_t)st.st_size + 1);
    size_t done = 0;
    while (buffer && done < (size_t)st.st_size) {
        ssize_t got = read(fd, buffer + done, (size_t)st.st_size - done);
        if (got <= 0) {
            free(buffer);
            buffer = NULL;
            break;
        }
        done += (size_t)got;
    }
    close(fd);
    *length = done;
    return buffer;
}

/* The main program's writable PT_LOAD segments: its .data, .bss and GOT. */
static int collect_segments(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    (void)data;
    if (info->dlpi_name && info->dlpi_name[0] != '\0')
        return 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_W))
            continue;
        if (g_n_segments == sizeof g_segments / sizeof g_segments[0])
            break;
        g_segments[g_n_segments].start = info->dlpi_addr + ph->p_vaddr;
        g_segments[g_n_segments].length = ph->p_memsz;
        g_segment_bytes += ph->p_memsz;
        g_n_segments++;
    }
    return 1;
}

/* ------------------------------------------------------------ child side */

static void child_capture(int how)
{
    struct slot_head *slot = g_child_slot;
    if (!slot)
        return;
    fflush(NULL);
    uint8_t *dst = (uint8_t *)(slot + 1);
    memcpy(dst, g_arena, g_head.arena_size);
    dst += g_head.arena_size;
    for (size_t i = 0; i < g_n_segments; i++) {
        memcpy(dst, (const void *)(uintptr_t)g_segments[i].start, g_segments[i].length);
        dst += g_segments[i].length;
    }
    /* What fd 1 and fd 2 held then (an emulator reports the signal on fd 2 after
     * it); unknown means all of it, never nothing. */
    struct stat st;
    slot->out_at_capture = fstat(1, &st) == 0 ? (uint64_t)st.st_size : UINT64_MAX;
    slot->err_at_capture = fstat(2, &st) == 0 ? (uint64_t)st.st_size : UINT64_MAX;
    slot->captured = how;
}

/* ADR D38: the counter overflows once, at the budget, into BUDGET_SIGNAL, whose default
 * action ends the run; settle ends a call that retired more by the read the same way. */
#define BUDGET_SIGNAL SIGPWR

static int g_counter = -1;
static uint64_t g_counter_budget;
static int g_counter_fake;
static uint64_t g_counter_fake_count;

/* A test's stand-in for the counter: the call retires `count`, whatever it does. */
static void counter_fake(uint64_t budget, uint64_t count)
{
    g_counter_budget = budget;
    g_counter_fake = 1;
    g_counter_fake_count = count;
}

static int counter_arm(uint64_t budget)
{
    g_counter_budget = budget;
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof attr;
    attr.config = PERF_COUNT_HW_INSTRUCTIONS;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.sample_period = budget + 1;  /* overflow at the first count past the budget */
    attr.wakeup_events = 1;
    int fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0)
        return errno;
    struct f_owner_ex owner = { .type = F_OWNER_TID, .pid = (pid_t)syscall(SYS_gettid) };
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_ASYNC) < 0
        || fcntl(fd, F_SETSIG, BUDGET_SIGNAL) < 0 || fcntl(fd, F_SETOWN_EX, &owner) < 0) {
        int error = errno;
        close(fd);
        return error;
    }
    g_counter = fd;
    return 0;
}

static void counter_start(void)
{
    if (g_counter >= 0)
        ioctl(g_counter, PERF_EVENT_IOC_REFRESH, 1);
}

static void counter_settle(void)
{
    uint64_t count = 0;
    if (g_counter_fake) {
        count = g_counter_fake_count;
    } else if (g_counter >= 0) {
        ioctl(g_counter, PERF_EVENT_IOC_DISABLE, 0);
        if (read(g_counter, &count, sizeof count) != (ssize_t)sizeof count)
            count = 0;
        close(g_counter);
        g_counter = -1;
    } else {
        return;
    }
    g_child_slot->insns = count;
    if (count > g_counter_budget)
        raise(BUDGET_SIGNAL);
}

static void child_exit_hook(void)
{
    if (g_in_call) {
        counter_settle();
        child_capture(CAPTURE_EXIT);
    }
}

static uintptr_t object_base(const void *address)
{
    Dl_info where;
    if (dladdr(address, &where) && where.dli_fbase)
        return (uintptr_t)where.dli_fbase;
    return 0;
}

/* Whether the trapping activation of the rendering is the one the thunk called:
 * the first frame inside the function must return into this runtime. */
static int trap_depth(void)
{
    void *frames[128];
    int n = backtrace(frames, 128);
    for (int i = 0; i < n; i++) {
        uintptr_t at = (uintptr_t)frames[i] - 1;
        if (at - g_child_fn >= g_child_fn_size)
            continue;
        if (i + 1 >= n)
            return TRAP_UNKNOWN;
        return object_base((const void *)((uintptr_t)frames[i + 1] - 1)) == g_rt_base
            ? TRAP_OUTERMOST : TRAP_NESTED;
    }
    return TRAP_UNKNOWN;
}

#define STACK_REACH 65536u

static void child_fault(int sig, siginfo_t *info, void *context)
{
    struct slot_head *slot = g_child_slot;
    if (slot && slot->fault_signal == 0) {
        ucontext_t *uc = context;
        slot->fault_signal = sig;
        slot->fault_pc = context_pc(uc);
        slot->fault_addr = (uint64_t)(uintptr_t)info->si_addr;
        /* A frame store past the stack's end faults within a frame of the stack pointer. */
        uint64_t sp = context_sp(uc);
        slot->fault_on_stack = (sig == SIGSEGV || sig == SIGBUS)
            && slot->fault_addr + STACK_REACH >= sp && slot->fault_addr <= sp + STACK_REACH;
        Dl_info where;
        if (dladdr((void *)(uintptr_t)slot->fault_pc, &where) && where.dli_fname) {
            strncpy(slot->fault_object, where.dli_fname, sizeof slot->fault_object - 1);
            slot->fault_base = (uint64_t)(uintptr_t)where.dli_fbase;
        }
        /* A trap in the rendering's own code: snapshot the state it reached. Its
         * stdio is quiescent there, so flushing it from the handler is safe. */
        if (sig == TRAP_SIGNAL && g_child_fn && slot->fault_base == g_child_own_base) {
            slot->trap_site = (uint32_t)context_arg0(uc);
            slot->trap_depth = trap_depth();
            child_capture(CAPTURE_TRAP);
        }
    }
    /* SA_RESETHAND restored the default action: returning re-executes the
     * faulting instruction, or abort() re-raises, and the child dies of the
     * same signal, which is what the parent reads. */
}

/* SIGTRAP in a rendering's child: a trap of the guarded original. */
static void child_guard(int sig, siginfo_t *info, void *context)
{
    ucontext_t *uc = context;
    uint64_t pc = trap_address(uc);
    uint64_t start = g_head.guard_start, end = start + g_head.guard_length;
    struct slot_head *slot = g_child_slot;
    if (pc < start || pc >= end || !slot) {
        /* Not the guard: a trap of the rendering's own, handled as any fault. */
        child_fault(sig, info, context);
        signal(SIGTRAP, SIG_DFL);
        raise(SIGTRAP);
        return;
    }
    int hit = GUARD_BODY;
    uint64_t caller = 0;
    if (pc == start) {
        caller = entry_return_address(uc);
        uintptr_t base = object_base((const void *)(uintptr_t)caller);
        /* A direct call from the rendering to another function that tail-jumped
         * here is a recursion through the program, not a delegation. */
        uint64_t called = base == g_guard_own_base ? direct_call_target(caller) : 0;
        if ((base != g_guard_own_base && base != g_guard_rt_base)
            || (called != 0 && called != start)) {
            /* The program called the function: it is the rendering now. The
             * registers and the stack are the caller's, exactly as a jump. */
            context_set_pc(uc, (uint64_t)(uintptr_t)g_guard_target);
            return;
        }
        hit = GUARD_DELEGATED;
    }
    if (slot->fault_signal == 0) {
        slot->guard = hit;
        slot->guard_caller = caller;
        slot->fault_signal = sig;
        slot->fault_pc = pc;
        slot->fault_addr = pc;
        Dl_info where;
        if (dladdr((void *)(uintptr_t)pc, &where) && where.dli_fname) {
            strncpy(slot->fault_object, where.dli_fname, sizeof slot->fault_object - 1);
            slot->fault_base = (uint64_t)(uintptr_t)where.dli_fbase;
        }
    }
    /* Die of this SIGTRAP as soon as the handler returns. */
    signal(SIGTRAP, SIG_DFL);
    raise(SIGTRAP);
}

/* Make the rendering the graded function: a trap over the original's code (a
 * private copy of the page, this child's alone), and SIGTRAP routed to
 * child_guard. */
static int guard_install(struct run_state *run)
{
    if (g_head.guard_length == 0)
        return 0;
    uintptr_t page = (uintptr_t)sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)g_head.guard_start, end = start + g_head.guard_length;
    uintptr_t low = start & ~(page - 1), high = (end + page - 1) & ~(page - 1);
    if (mprotect((void *)low, high - low, PROT_READ | PROT_WRITE) != 0)
        return errno;
    trap_fill((uint8_t *)start, g_head.guard_length);
    if (mprotect((void *)low, high - low, PROT_READ | PROT_EXEC) != 0)
        return errno;
    /* No stale copy of the old instructions may run (a no-op on x86-64). */
    __builtin___clear_cache((char *)start, (char *)end);
    g_guard_target = run->fn;
    g_guard_own_base = object_base(run->fn);
    g_guard_rt_base = object_base((const void *)guard_install);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = child_guard;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTRAP, &sa, NULL);
    return 0;
}

static void child_run(struct run_state *run, const struct job_vector *vec, uint64_t budget)
{
    dup2(run->out_fd, 1);
    dup2(run->err_fd, 2);

    static uint8_t altstack[1 << 16];
    stack_t ss = { .ss_sp = altstack, .ss_size = sizeof altstack, .ss_flags = 0 };
    sigaltstack(&ss, NULL);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = child_fault;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    int faults[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT, SIGTRAP, SIGSYS };
    for (size_t i = 0; i < sizeof faults / sizeof faults[0]; i++)
        sigaction(faults[i], &sa, NULL);
    signal(SIGALRM, SIG_DFL);
    signal(SIGPIPE, SIG_DFL);
    signal(BUDGET_SIGNAL, SIG_DFL);
    /* The signal mask is inherited, and a blocked SIGALRM arms a timer that never fires. */
    sigset_t none;
    sigemptyset(&none);
    sigprocmask(SIG_SETMASK, &none, NULL);
    /* Under the time measure the budget is the guard; under instructions, hang_ms is. */
    int guard_ms = g_head.measure == MEASURE_TIME ? (int)budget : (int)g_head.hang_ms;
    struct rlimit cpu;
    cpu.rlim_cur = (rlim_t)(guard_ms / 1000) * 2 + 2;
    cpu.rlim_max = cpu.rlim_cur + 1;
    setrlimit(RLIMIT_CPU, &cpu);

    g_child_slot = run->slot;
    if (g_head.measure == MEASURE_INSTRUCTIONS) {
        int error = 0;
        if (g_head.fake_count)
            counter_fake(budget, run->spec->replaces ? g_head.fake_count : 0);
        else
            error = counter_arm(budget);
        if (error) {
            run->slot->counter_error = error;
            _exit(0);
        }
    }
    atexit(child_exit_hook);
    if (run->spec->replaces) {
        Dl_info where;
        const ElfW(Sym) *symbol = NULL;
        g_child_fn = (uintptr_t)run->fn;
        if (dladdr1(run->fn, &where, (void **)&symbol, RTLD_DL_SYMENT) && symbol)
            g_child_fn_size = symbol->st_size;
        g_child_own_base = object_base(run->fn);
        g_rt_base = object_base((const void *)child_run);
        int error = guard_install(run);
        if (error) {
            run->slot->guard_error = error;
            _exit(0);
        }
    }

    struct itimerval timer;
    memset(&timer, 0, sizeof timer);
    timer.it_value.tv_sec = guard_ms / 1000;
    timer.it_value.tv_usec = (guard_ms % 1000) * 1000;
    setitimer(ITIMER_REAL, &timer, NULL);

    struct equiv_ret ret;
    memset(&ret, 0, sizeof ret);
    g_in_call = 1;
    counter_start();
    equiv_call(run->fn, &vec->regs, &ret);
    counter_settle();
    g_in_call = 0;

    memset(&timer, 0, sizeof timer);
    setitimer(ITIMER_REAL, &timer, NULL);
    run->slot->ret = ret;
    child_capture(CAPTURE_RETURN);
    _exit(0);
}

/* ----------------------------------------------------------- parent side */

static size_t read_capture(int fd, char *buffer, size_t cap, size_t *total)
{
    struct stat st;
    *total = 0;
    if (fstat(fd, &st) != 0)
        return 0;
    *total = (size_t)st.st_size;
    size_t want = *total < cap ? *total : cap;
    size_t done = 0;
    while (done < want) {
        ssize_t got = pread(fd, buffer + done, want - done, (off_t)done);
        if (got <= 0)
            break;
        done += (size_t)got;
    }
    return done;
}

static void run_one(struct run_state *run, const struct job_vector *vec, uint64_t budget)
{
    memset(run->slot, 0, sizeof *run->slot);
    /* Empty both captures and rewind them. The offset belongs to the open file
     * description every child shares through dup2, so without the rewind a
     * run's bytes would land after everything it wrote on earlier vectors, and
     * two runs that once wrote different amounts would never line up again. */
    if (ftruncate(run->out_fd, 0) != 0 || ftruncate(run->err_fd, 0) != 0
        || lseek(run->out_fd, 0, SEEK_SET) != 0 || lseek(run->err_fd, 0, SEEK_SET) != 0) {
        run->outcome = OUT_UNAVAILABLE;
        snprintf(run->load_error, sizeof run->load_error, "resetting the captures: %s",
                 strerror(errno));
        return;
    }
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        run->outcome = OUT_UNAVAILABLE;
        snprintf(run->load_error, sizeof run->load_error, "fork: %s", strerror(errno));
        return;
    }
    if (pid == 0)
        child_run(run, vec, budget);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }

    if (run->slot->counter_error) {
        run->outcome = OUT_UNAVAILABLE;
        snprintf(run->load_error, sizeof run->load_error, "perf_event_open: %s",
                 strerror(run->slot->counter_error));
        return;
    }
    if (run->slot->guard_error) {
        run->outcome = OUT_UNAVAILABLE;
        snprintf(run->load_error, sizeof run->load_error,
                 "cannot put the rendering in place of the original: %s",
                 strerror(run->slot->guard_error));
        return;
    }
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (sig == BUDGET_SIGNAL && g_head.measure == MEASURE_INSTRUCTIONS)
            run->outcome = OUT_BUDGET;
        else if (sig == SIGALRM)
            run->outcome = g_head.measure == MEASURE_TIME ? OUT_BUDGET : OUT_HANG;
        else
            run->outcome = OUT_SIGNAL;
        run->status = sig;
    } else if (WIFEXITED(status)) {
        run->status = WEXITSTATUS(status);
        if (run->slot->captured == CAPTURE_RETURN && run->status == 0)
            run->outcome = OUT_RETURN;
        else if (run->slot->captured == CAPTURE_EXIT)
            run->outcome = OUT_EXIT;
        else
            run->outcome = OUT_EXIT_RAW;
    } else {
        run->outcome = OUT_SIGNAL;
        run->status = 0;
    }
    run->out_len = read_capture(run->out_fd, run->out_buf, g_head.out_cap, &(size_t){ 0 });
    run->err_len = read_capture(run->err_fd, run->err_buf, g_head.out_cap, &(size_t){ 0 });
}

static int is_nan_bits(const uint8_t *bytes, int width)
{
    if (width == 4) {
        uint32_t v;
        memcpy(&v, bytes, 4);
        return (v & 0x7f800000u) == 0x7f800000u && (v & 0x007fffffu) != 0;
    }
    uint64_t v;
    memcpy(&v, bytes, 8);
    return (v & 0x7ff0000000000000ull) == 0x7ff0000000000000ull && (v & 0x000fffffffffffffull) != 0;
}

/* The first differing byte of two regions, or -1. */
static long first_difference(const uint8_t *a, const uint8_t *b, size_t length)
{
    if (memcmp(a, b, length) == 0)
        return -1;
    for (size_t i = 0; i < length; i++)
        if (a[i] != b[i])
            return (long)i;
    return -1;
}

/* Where two captured states first differ. */
struct difference {
    const char *field;
    uint64_t address;
    const uint8_t *a;
    const uint8_t *b;
    size_t available;
};

/* The first byte at which two captured states differ (the arena, then the
 * writable segments): 1 with *out filled, or 0 when they agree. */
static int state_difference(const struct run_state *a, const struct run_state *b,
                            struct difference *out)
{
    const uint8_t *ba = (const uint8_t *)(a->slot + 1);
    const uint8_t *bb = (const uint8_t *)(b->slot + 1);
    long at = first_difference(ba, bb, g_head.arena_size);
    if (at >= 0) {
        *out = (struct difference){ "arena", g_head.arena_base + (uint64_t)at, ba + at, bb + at,
                                    g_head.arena_size - (size_t)at };
        return 1;
    }
    ba += g_head.arena_size;
    bb += g_head.arena_size;
    for (size_t i = 0; i < g_n_segments; i++) {
        at = first_difference(ba, bb, g_segments[i].length);
        if (at >= 0) {
            *out = (struct difference){ "memory", g_segments[i].start + (uint64_t)at, ba + at,
                                        bb + at, g_segments[i].length - (size_t)at };
            return 1;
        }
        ba += g_segments[i].length;
        bb += g_segments[i].length;
    }
    return 0;
}

static void emit_difference(const struct difference *d)
{
    size_t window = d->available < 16 ? d->available : 16;
    fprintf(g_out, ",\"field\":\"%s\",\"address\":\"0x%llx\",\"a_bytes\":", d->field,
            (unsigned long long)d->address);
    json_hex(g_out, d->a, window);
    fputs(",\"b_bytes\":", g_out);
    json_hex(g_out, d->b, window);
}

/* Whether the first min(part_len, at) bytes of part begin whole. */
static int is_prefix(const char *part, size_t part_len, uint64_t at, const char *whole,
                     size_t whole_len)
{
    size_t length = part_len < at ? part_len : (size_t)at;
    return length <= whole_len && memcmp(part, whole, length) == 0;
}

/* A rendering that trapped, against the original's end: whether its output by the
 * trap is a prefix of the original's, and where their states differ; gate.py decides. */
static void emit_pre_trap(const struct run_state *a, const struct run_state *b)
{
    struct difference d;
    int differs = state_difference(a, b, &d);
    const struct slot_head *trap = b->slot;
    fprintf(g_out, ",\"pre_trap\":{\"stdout\":%s,\"stderr\":%s,\"memory\":%s",
            is_prefix(b->out_buf, b->out_len, trap->out_at_capture, a->out_buf, a->out_len)
                ? "true" : "false",
            is_prefix(b->err_buf, b->err_len, trap->err_at_capture, a->err_buf, a->err_len)
                ? "true" : "false",
            differs ? "false" : "true");
    if (differs)
        emit_difference(&d);
    fputc('}', g_out);
}

/* Compare two runs. Writes the fields after "equal": into g_out. */
static void compare_runs(const struct run_state *a, const struct run_state *b)
{
    if (a->outcome != b->outcome) {
        fputs("false,\"field\":\"exit\"", g_out);
        if ((a->outcome == OUT_RETURN || a->outcome == OUT_EXIT) && a->slot->captured
            && b->outcome == OUT_SIGNAL && b->slot->captured == CAPTURE_TRAP)
            emit_pre_trap(a, b);
        return;
    }
    switch (a->outcome) {
    case OUT_SIGNAL:
    case OUT_EXIT_RAW:
        if (a->status != b->status) {
            fputs("false,\"field\":\"exit\"", g_out);
            return;
        }
        break;
    case OUT_EXIT:
        if (a->status != b->status) {
            fputs("false,\"field\":\"exit\"", g_out);
            return;
        }
        break;
    default:
        break;
    }

    if (a->outcome == OUT_RETURN) {
        const struct equiv_ret *ra = &a->slot->ret, *rb = &b->slot->ret;
        int differs = 0;
        uint8_t va[16], vb[16];
        size_t width = 0;
        memset(va, 0, sizeof va);
        memset(vb, 0, sizeof vb);
        switch (g_head.ret_kind) {
        case RET_INT:
            width = g_head.ret_bytes;
            memcpy(va, &ra->r0, width);
            memcpy(vb, &rb->r0, width);
            differs = memcmp(va, vb, width) != 0;
            break;
        case RET_INT128:
            width = 16;
            memcpy(va, &ra->r0, 8);
            memcpy(va + 8, &ra->r1, 8);
            memcpy(vb, &rb->r0, 8);
            memcpy(vb + 8, &rb->r1, 8);
            differs = memcmp(va, vb, width) != 0;
            break;
        case RET_F32:
        case RET_F64:
            width = g_head.ret_kind == RET_F32 ? 4 : 8;
            memcpy(va, ra->f0, width);
            memcpy(vb, rb->f0, width);
            /* Two NaNs are the same answer whatever their payload. */
            differs = memcmp(va, vb, width) != 0
                && !(is_nan_bits(va, (int)width) && is_nan_bits(vb, (int)width));
            break;
        default:
            break;
        }
        if (differs) {
            fputs("false,\"field\":\"return\",\"a_bytes\":", g_out);
            json_hex(g_out, va, width);
            fputs(",\"b_bytes\":", g_out);
            json_hex(g_out, vb, width);
            return;
        }
    }

    if ((a->outcome == OUT_RETURN || a->outcome == OUT_EXIT) && a->slot->captured
        && b->slot->captured) {
        struct difference d;
        if (state_difference(a, b, &d)) {
            fputs("false", g_out);
            emit_difference(&d);
            return;
        }
    }

    if (a->out_len != b->out_len || memcmp(a->out_buf, b->out_buf, a->out_len) != 0) {
        fputs("false,\"field\":\"stdout\"", g_out);
        return;
    }
    if (a->err_len != b->err_len || memcmp(a->err_buf, b->err_buf, a->err_len) != 0) {
        fputs("false,\"field\":\"stderr\"", g_out);
        return;
    }
    fputs("true", g_out);
}

static void emit_run(size_t index, const struct run_state *run)
{
    fprintf(g_out, "{\"run\":%zu,\"outcome\":\"%s\"", index, outcome_name[run->outcome]);
    if (run->outcome == OUT_SIGNAL || run->outcome == OUT_EXIT || run->outcome == OUT_EXIT_RAW)
        fprintf(g_out, ",\"status\":%d", run->status);
    if (run->outcome == OUT_SIGNAL && run->slot->fault_signal) {
        fprintf(g_out,
                ",\"fault_pc\":\"0x%llx\",\"fault_addr\":\"0x%llx\",\"fault_base\":\"0x%llx\","
                "\"fault_object\":",
                (unsigned long long)run->slot->fault_pc,
                (unsigned long long)run->slot->fault_addr,
                (unsigned long long)run->slot->fault_base);
        json_string(g_out, run->slot->fault_object, strlen(run->slot->fault_object));
        if (run->slot->fault_on_stack)
            fputs(",\"stack\":true", g_out);
        if (run->slot->guard) {
            fprintf(g_out, ",\"guard\":\"%s\"", guard_name[run->slot->guard]);
            Dl_info where;
            if (run->slot->guard_caller
                && dladdr((void *)(uintptr_t)run->slot->guard_caller, &where) && where.dli_fname) {
                fprintf(g_out, ",\"guard_caller_offset\":\"0x%llx\",\"guard_caller_object\":",
                        (unsigned long long)(run->slot->guard_caller
                                             - (uint64_t)(uintptr_t)where.dli_fbase));
                json_string(g_out, where.dli_fname, strlen(where.dli_fname));
            }
        }
        if (run->slot->captured == CAPTURE_TRAP)
            fprintf(g_out, ",\"trap_site\":%u,\"trap_depth\":\"%s\"", run->slot->trap_site,
                    trap_depth_name[run->slot->trap_depth]);
    }
    /* A skipped or unloaded run's slot still holds the last vector's count. */
    if (run->slot->insns && run->outcome != OUT_SKIPPED && run->outcome != OUT_UNAVAILABLE)
        fprintf(g_out, ",\"insns\":%llu", (unsigned long long)run->slot->insns);
    if (run->outcome == OUT_RETURN) {
        fputs(",\"" RET_INT_NAME "\":", g_out);
        json_hex(g_out, (const uint8_t *)&run->slot->ret.r0, 8);
        fputs(",\"" RET_FP_NAME "\":", g_out);
        json_hex(g_out, run->slot->ret.f0, 8);
    }
    if (run->out_len) {
        size_t shown = run->out_len < 256 ? run->out_len : 256;
        fputs(",\"stdout\":", g_out);
        json_string(g_out, run->out_buf, shown);
    }
    if (run->err_len) {
        size_t shown = run->err_len < 1024 ? run->err_len : 1024;
        fputs(",\"stderr\":", g_out);
        json_string(g_out, run->err_buf, shown);
    }
    if (run->outcome == OUT_UNAVAILABLE && run->load_error[0]) {
        fputs(",\"error\":", g_out);
        json_string(g_out, run->load_error, strlen(run->load_error));
    }
    fputc('}', g_out);
}

static int equiv_main(int argc, char **argv, char **envp)
{
    (void)argc;
    (void)argv;
    (void)envp;
    const char *job_path = getenv("EQUIV_JOB");
    const char *out_path = getenv("EQUIV_OUT");
    if (!out_path)
        return die("EQUIV_OUT is not set");
    g_out = fopen(out_path, "we");
    if (!g_out) {
        fprintf(stderr, "equiv_rt: cannot open %s: %s\n", out_path, strerror(errno));
        return 70;
    }
    size_t job_length = 0;
    uint8_t *job = read_file(job_path, &job_length);
    if (!job || job_length < sizeof g_head)
        return die("cannot read the job file");
    memcpy(&g_head, job, sizeof g_head);
    if (memcmp(g_head.magic, JOB_MAGIC, 8) != 0)
        return die("the job file has the wrong magic");
    size_t at = sizeof g_head;
    if (at + g_head.n_runs * sizeof(struct job_run) + g_head.n_pairs * sizeof(struct job_pair)
        > job_length)
        return die("the job file is truncated");
    const struct job_run *specs = (const struct job_run *)(job + at);
    at += g_head.n_runs * sizeof(struct job_run);
    const struct job_pair *pairs = (const struct job_pair *)(job + at);
    at += g_head.n_pairs * sizeof(struct job_pair);

    void *arena = mmap((void *)(uintptr_t)g_head.arena_base, g_head.arena_size,
                       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                       -1, 0);
    if (arena == MAP_FAILED || (uint64_t)(uintptr_t)arena != g_head.arena_base)
        return die("cannot map the arena at its fixed address");
    g_arena = arena;

    if (g_head.measure == MEASURE_INSTRUCTIONS && !g_head.fake_count) {
        int error = counter_arm(1);
        if (error) {
            char what[160];
            snprintf(what, sizeof what, "perf_event_open: %s", strerror(error));
            return die(what);
        }
        close(g_counter);
        g_counter = -1;
    }

    dl_iterate_phdr(collect_segments, NULL);
    /* backtrace() loads its unwinder on first use: do it here, never in a handler. */
    void *warm[1];
    backtrace(warm, 1);
    if (g_n_segments == 0)
        return die("the main program has no writable segment");

    g_runs = calloc(g_head.n_runs, sizeof *g_runs);
    if (!g_runs)
        return die("out of memory");
    for (uint32_t i = 0; i < g_head.n_runs; i++) {
        struct run_state *run = &g_runs[i];
        run->spec = &specs[i];
        run->slot_size = sizeof(struct slot_head) + g_head.arena_size + g_segment_bytes;
        run->slot = mmap(NULL, run->slot_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (run->slot == MAP_FAILED)
            return die("cannot map a result slot");
        run->out_fd = memfd_create("equiv-stdout", MFD_CLOEXEC);
        run->err_fd = memfd_create("equiv-stderr", MFD_CLOEXEC);
        run->out_buf = malloc(g_head.out_cap + 1);
        run->err_buf = malloc(g_head.out_cap + 1);
        if (run->out_fd < 0 || run->err_fd < 0 || !run->out_buf || !run->err_buf)
            return die("cannot create the capture files");
        if (run->spec->so_path[0] == '\0') {
            run->fn = (void *)(uintptr_t)run->spec->address;
            continue;
        }
        run->handle = dlopen(run->spec->so_path, RTLD_NOW | RTLD_LOCAL);
        if (!run->handle) {
            snprintf(run->load_error, sizeof run->load_error, "dlopen: %s", dlerror());
            continue;
        }
        run->fn = dlsym(run->handle, run->spec->symbol);
        if (!run->fn)
            snprintf(run->load_error, sizeof run->load_error, "dlsym %s: %s", run->spec->symbol,
                     dlerror());
    }

    fprintf(g_out, "{\"runs\":[");
    for (uint32_t i = 0; i < g_head.n_runs; i++) {
        fprintf(g_out, "%s{\"run\":%u,\"label\":", i ? "," : "", i);
        json_string(g_out, g_runs[i].spec->label, strlen(g_runs[i].spec->label));
        if (!g_runs[i].fn) {
            fputs(",\"error\":", g_out);
            json_string(g_out, g_runs[i].load_error, strlen(g_runs[i].load_error));
        }
        fputc('}', g_out);
    }
    fprintf(g_out, "],\"segments\":[");
    for (size_t i = 0; i < g_n_segments; i++)
        fprintf(g_out, "%s[\"0x%llx\",%llu]", i ? "," : "",
                (unsigned long long)g_segments[i].start,
                (unsigned long long)g_segments[i].length);
    fprintf(g_out, "]}\n");
    fflush(g_out);

    for (uint32_t v = 0; v < g_head.n_vectors; v++) {
        if (at + sizeof(struct job_vector) > job_length)
            return die("the job file ends inside a vector");
        const struct job_vector *vec = (const struct job_vector *)(job + at);
        at += sizeof *vec;

        uint64_t state = vec->seed;
        uint64_t *words = (uint64_t *)g_arena;
        for (size_t i = 0; i < g_head.arena_size / 8; i++)
            words[i] = splitmix64(&state);
        for (uint32_t p = 0; p < vec->n_patches; p++) {
            if (at + sizeof(struct job_patch) > job_length)
                return die("the job file ends inside a patch");
            const struct job_patch *patch = (const struct job_patch *)(job + at);
            at += sizeof *patch;
            if (patch->offset > g_head.arena_size
                || patch->length > g_head.arena_size - patch->offset
                || at + patch->length > job_length)
                return die("a patch lies outside the arena or the job");
            memcpy(g_arena + patch->offset, job + at, patch->length);
            at += (patch->length + 7) & ~(uint64_t)7;
        }

        /* Run 0 is the original. When it does not return or exit normally,
         * the vector lies outside the function's defined domain and the
         * renderings are not asked. */
        int original_ok = 1;
        for (uint32_t r = 0; r < g_head.n_runs; r++) {
            struct run_state *run = &g_runs[r];
            run->out_len = run->err_len = 0;
            run->status = 0;
            if (!run->fn) {
                run->outcome = OUT_UNAVAILABLE;
                continue;
            }
            if (r > 0 && !original_ok) {
                run->outcome = OUT_SKIPPED;
                continue;
            }
            run_one(run, vec, r == 0 ? g_head.budget : g_head.budget * 4);
            if (r == 0)
                original_ok = run->outcome == OUT_RETURN || run->outcome == OUT_EXIT;
        }

        fprintf(g_out, "{\"vector\":%u,\"runs\":[", v);
        for (uint32_t r = 0; r < g_head.n_runs; r++) {
            if (r)
                fputc(',', g_out);
            emit_run(r, &g_runs[r]);
        }
        fputs("],\"pairs\":[", g_out);
        int first = 1;
        for (uint32_t p = 0; p < g_head.n_pairs; p++) {
            const struct run_state *a = &g_runs[pairs[p].a], *b = &g_runs[pairs[p].b];
            if (pairs[p].a >= g_head.n_runs || pairs[p].b >= g_head.n_runs)
                continue;
            if (a->outcome == OUT_SKIPPED || b->outcome == OUT_SKIPPED
                || a->outcome == OUT_UNAVAILABLE || b->outcome == OUT_UNAVAILABLE
                || a->outcome == OUT_HANG || b->outcome == OUT_HANG)
                continue;
            fprintf(g_out, "%s{\"a\":%u,\"b\":%u,\"equal\":", first ? "" : ",", pairs[p].a,
                    pairs[p].b);
            compare_runs(a, b);
            fputc('}', g_out);
            first = 0;
        }
        fputs("]}\n", g_out);
        fflush(g_out);
    }
    fputs("{\"done\":true}\n", g_out);
    fclose(g_out);
    free(job);
    return 0;
}

typedef int (*main_fn)(int, char **, char **);
typedef int (*start_fn)(main_fn, int, char **, void (*)(void), void (*)(void), void (*)(void),
                        void *);

int __libc_start_main(main_fn main, int argc, char **argv, void (*init)(void),
                      void (*fini)(void), void (*rtld_fini)(void), void *stack_end)
{
    start_fn real = (start_fn)dlsym(RTLD_NEXT, "__libc_start_main");
    if (!real)
        _exit(71);
    if (getenv("EQUIV_JOB"))
        return real(equiv_main, argc, argv, init, fini, rtld_fini, stack_end);
    return real(main, argc, argv, init, fini, rtld_fini, stack_end);
}
