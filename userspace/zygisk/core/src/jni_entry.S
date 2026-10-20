/*
 * Per-signature JNI entry stubs for the zygote lifecycle hooks.
 *
 * RegisterNatives installs a plain function pointer, so the wrapper never
 * passes through the inline-hook capture trampoline that records the caller
 * context. Each stub records the same context into g_yz_ret_ctx and then
 * tail-branches to the C++ wrapper, which lets yz_self_unmap_tail restore a
 * continuation outside the core before unmapping it.
 */

.section .note.GNU-stack,"",%progbits

#if defined(__aarch64__)

.text
.balign 4

.macro YZ_JNI_ENTRY name, index
    .global \name
    .hidden \name
    .type \name, %function
\name:
    hint #34
    adrp x16, g_yz_ret_ctx
    add  x16, x16, :lo12:g_yz_ret_ctx
    stp  x19, x20, [x16, #0]
    stp  x21, x22, [x16, #16]
    stp  x23, x24, [x16, #32]
    stp  x25, x26, [x16, #48]
    stp  x27, x28, [x16, #64]
    stp  x29, x30, [x16, #80]
    mov  x17, sp
    str  x17, [x16, #96]
    stp  d8,  d9,  [x16, #104]
    stp  d10, d11, [x16, #120]
    stp  d12, d13, [x16, #136]
    stp  d14, d15, [x16, #152]
    adrp x16, g_yz_jni_targets
    add  x16, x16, :lo12:g_yz_jni_targets
    ldr  x16, [x16, #(\index * 8)]
    br   x16
    .size \name, .-\name
.endm

YZ_JNI_ENTRY yz_jni_entry_0, 0
YZ_JNI_ENTRY yz_jni_entry_1, 1
YZ_JNI_ENTRY yz_jni_entry_2, 2
YZ_JNI_ENTRY yz_jni_entry_3, 3
YZ_JNI_ENTRY yz_jni_entry_4, 4
YZ_JNI_ENTRY yz_jni_entry_5, 5
YZ_JNI_ENTRY yz_jni_entry_6, 6
YZ_JNI_ENTRY yz_jni_entry_7, 7

#endif
