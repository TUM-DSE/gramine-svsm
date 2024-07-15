# Arch-specific meson.build must define the following Meson variables:
#   - `pal_skeleton_lds` - a full path to PAL linker script.
subdir('arch')

pal_svsm_map = custom_target('pal.map[svsm]',
    command: [gen_pal_map_prog, '@INPUT@', '@OUTPUT@'],
    input: ['../../pal_symbols', 'pal.map.template'],
    output: 'pal.map',
)

libpal_svsm = shared_library('pal',
    'pal_console.c',
    'pal_devices.c',
    'pal_eventfd.c',
    'pal_events.c',
    'pal_exception.c',
    'pal_files.c',
    'pal_main.c',
    'pal_memory.c',
    'pal_misc.c',
    'pal_object.c',
    'pal_pipes.c',
    'pal_process.c',
    'pal_rtld.c',
    'pal_sockets.c',
    'pal_streams.c',
    'pal_threading.c',
    'arch/x86_64/pal_start.S',
    pal_common_sources,

    include_directories: [
        includes_pal_common,
        include_directories(
            '../../../include/arch/@0@/svsm'.format(host_machine.cpu_family()),
        ),
    ],

    c_args: [
        cflags_pal_common,
        cflags_custom_stack_protector,
        cflags_sanitizers,
        '-DHOST_TYPE=Svsm',

        # in Skeleton, every single parameter is unused
        '-Wno-unused-parameter',
    ],

    link_args: [
        '-nostdlib',

        # For PAL symbol resolution, we use old-style hash (DT_HASH) table instead of the
        # default GNU hash (DT_GNU_HASH) table -- to figure out the number of dynamic symbols in
        # the SYMTAB symbol table
        '-Wl,--hash-style=sysv',

        # PAL is expected to be linked with RELRO (Relocation Read-Only)
        '-Wl,-zrelro',
        '-Wl,-znow',

        '-Wl,-zcombreloc',
        '-Wl,-zdefs',
        '-Wl,--version-script=@0@'.format(pal_svsm_map.full_path()),
        '-Wl,-T@0@'.format(pal_svsm_lds),
        '-Wl,--eh-frame-hdr',
    ],
    link_depends: [
        pal_svsm_map,
        pal_svsm_lds,
    ],

    dependencies: [
        common_dep,
    ],

    install: true,
    install_dir: pkglibdir / 'svsm',
)


libpal_svsm_dep = declare_dependency(
    link_with: libpal_svsm,
)
if debug
    custom_target('libpal.so.map',
        input: libpal_direct,
        command: gen_symbol_map_cmd,
        capture: true,
        output: 'libpal.so.map',

        install: true,
        install_dir: pkglibdir / 'svsm',
    )

endif

meson.add_install_script('/bin/sh', '-c',
    'ln -sf libpal.so "$MESON_INSTALL_DESTDIR_PREFIX"/@0@'.format(
        pkglibdir / 'svsm/loader'))

