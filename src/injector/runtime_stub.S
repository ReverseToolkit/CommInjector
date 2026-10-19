// 注入进目标进程的运行时。地址都相对本段，data 由注入器填好。
// tls_get_addr(TlsIndex*)：module_id 等于 data.module_id 时用本模块的块，否则转系统实现。
// tlsdesc(desc*)：AArch64 TLSDESC，只允许改 x0，返回值是地址减去 TPIDR_EL0。
// cxa_atexit / cxa_thread_atexit / register_atfork：直接返回 0，不写入 libc 的回调表。

.section .text
.global blob_start
.global tls_get_addr
.global tlsdesc
.global cxa_atexit
.global cxa_thread_atexit
.global register_atfork
.global data_start

.balign 4
blob_start:

tls_get_addr:
    stp x29, x30, [sp, #-64]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    mov x19, x0
    ldr x20, [x0]            // module id
    ldr x21, [x0, #8]        // offset
    adr x22, data_start
    ldr x23, [x22, #80]      // our module id
    cmp x20, x23
    b.ne .Lforward
    ldr w0, [x22]            // pthread_key_t
    ldr x1, [x22, #64]       // pthread_getspecific
    blr x1
    cbnz x0, .Lhave
    mov x0, #1
    ldr x1, [x22, #8]        // tls memsz
    ldr x2, [x22, #48]       // calloc
    blr x2
    cbz x0, .Lfail
    mov x24, x0
    ldr x1, [x22, #24]       // template
    ldr x2, [x22, #32]       // template filesz
    cbz x2, .Lset
    mov x0, x24
    ldr x3, [x22, #56]       // memcpy
    blr x3
.Lset:
    ldr w0, [x22]
    mov x1, x24
    ldr x2, [x22, #72]       // pthread_setspecific
    blr x2
    mov x0, x24
.Lhave:
    add x0, x0, x21
    b .Lret
.Lforward:
    mov x0, x19
    ldr x1, [x22, #40]       // libc __tls_get_addr
    blr x1
    b .Lret
.Lfail:
    mov x0, xzr
.Lret:
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret

// x0 = descriptor*. 保存 tls_get_addr 会破坏的寄存器。
tlsdesc:
    sub sp, sp, #(8 * 80)
    stp x29, x30, [sp]
    stp x1, x2, [sp, #16]
    stp x3, x4, [sp, #32]
    stp x5, x6, [sp, #48]
    stp x7, x8, [sp, #64]
    stp x9, x10, [sp, #80]
    stp x11, x12, [sp, #96]
    stp x13, x14, [sp, #112]
    stp x15, x16, [sp, #128]
    str x17, [sp, #144]
    stp q0, q1, [sp, #160]
    stp q2, q3, [sp, #192]
    stp q4, q5, [sp, #224]
    stp q6, q7, [sp, #256]
    ldr x0, [x0, #8]
    bl tls_get_addr
    mrs x1, tpidr_el0
    sub x0, x0, x1
    ldp q6, q7, [sp, #256]
    ldp q4, q5, [sp, #224]
    ldp q2, q3, [sp, #192]
    ldp q0, q1, [sp, #160]
    ldr x17, [sp, #144]
    ldp x15, x16, [sp, #128]
    ldp x13, x14, [sp, #112]
    ldp x11, x12, [sp, #96]
    ldp x9, x10, [sp, #80]
    ldp x7, x8, [sp, #64]
    ldp x5, x6, [sp, #48]
    ldp x3, x4, [sp, #32]
    ldp x1, x2, [sp, #16]
    ldp x29, x30, [sp]
    add sp, sp, #(8 * 80)
    ret

cxa_atexit:
cxa_thread_atexit:
register_atfork:
    mov w0, #0
    ret

// 未定义的弱 TLS：描述符 arg 就是 addend，返回 addend - TP。
.global tlsdesc_weak
tlsdesc_weak:
    ldr x0, [x0, #8]
    mrs x1, tpidr_el0
    sub x0, x0, x1
    ret

.balign 8
data_start:
    .quad 0          // 0  key (low 32 bits)
    .quad 0          // 8  tls memsz
    .quad 0          // 16 align
    .quad 0          // 24 template
    .quad 0          // 32 template size
    .quad 0          // 40 libc __tls_get_addr
    .quad 0          // 48 calloc
    .quad 0          // 56 memcpy
    .quad 0          // 64 pthread_getspecific
    .quad 0          // 72 pthread_setspecific
    .quad 0          // 80 module id
    .space 64 * 16   // TLSDESC 参数表，每项 {module_id, offset}
