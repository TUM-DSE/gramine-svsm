cflags_libos = [
    '-fPIC',
    # TODO: check whether all standard functions implemented in Gramine match their APIs and remove
    # this
    '-ffreestanding',

    '-DIN_LIBOS',
]

cflags_libos += cc.get_supported_arguments(
    # Some of the code uses alignof on expressions, which is a GNU extension.
    # Silence Clang - it complains but does support it.
    '-Wno-gnu-alignof-expression',
)

if host_machine.cpu_family() == 'x86_64'
    cflags_libos += ['-mfxsr', '-mxsave']
endif

# glibc >= 2.41 cancels a thread blocked in a syscall only if its PC lies in the
# cancellable syscall sequence; restart_syscall() then rewinds to the caller's
# instruction(s) (libos_context.c). Only for such a glibc, so a 2.40 build's
# LibOS is the same bytes as before the option.
if get_option('libc') == 'glibc' and get_option('glibc_version') != '2.40'
    cflags_libos += '-DLIBOS_RESTART_AT_CALLER'
endif

subdir('include')
subdir('src')

if enable_tests
    subdir('test')
endif
