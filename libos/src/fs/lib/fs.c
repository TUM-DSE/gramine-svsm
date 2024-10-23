#include "libos_fs.h"
#include "libos_fs_pseudo.h"

#include "ld.c"
#include "libc.c"
#include "libm.c"
#include "libz.c"
#include "libexpat.c"
#include "libblas.c"
#include "libgcc_s.c"
#include "liblapack.c"
#include "libgfortran.c"
#include "libffi.c"
#include "libstdc++.c"

static int ld(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) ld_linux_x86_64_so_2;
    *out_size = ld_linux_x86_64_so_2_len;
    return 0;
}

static int libc(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libc_so_6;
    *out_size = libc_so_6_len;
    return 0;
}

static int libm(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libm_so_6;
    *out_size = libm_so_6_len;
    return 0;
}

static int libz(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libz_so_1;
    *out_size = libz_so_1_len;
    return 0;
}

static int libexpat(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libexpat_so_1;
    *out_size = libexpat_so_1_len;
    return 0;
}

static int libblas(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libblas_so_3;
    *out_size = libblas_so_3_len;
    return 0;
}

static int libgcc_s(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libgcc_s_so_1;
    *out_size = libgcc_s_so_1_len;
    return 0;
}

static int liblapack(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) liblapack_so_3;
    *out_size = liblapack_so_3_len;
    return 0;
}

static int libgfortran(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libgfortran_so_5;
    *out_size = libgfortran_so_5_len;
    return 0;
}

static int libffi(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libffi_so_8;
    *out_size = libffi_so_8_len;
    return 0;
}

static int libstdcpp(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libstdc___so_6;
    *out_size = libstdc___so_6_len;
    return 0;
}

int init_libfs(void) {
    struct pseudo_node* root = pseudo_add_root_dir("lib");

    // ld-linux-x86-64.so.2 is the loader for dynamically linked executables
    struct pseudo_node* node = pseudo_add_str(root, "ld-linux-x86-64.so.2", &ld);
    node->str.no_free = true;

    // libc.so.6 is the C standard library
    node = pseudo_add_str(root, "libc.so.6", &libc);
    node->str.no_free = true;

    // libm.so.6 is needed for python
    node = pseudo_add_str(root, "libm.so.6", &libm);
    node->str.no_free = true;

    // libz.so.1 is needed for python
    node = pseudo_add_str(root, "libz.so.1", &libz);
    node->str.no_free = true;

    // libexpat.so.1 is needed for python
    node = pseudo_add_str(root, "libexpat.so.1", &libexpat);
    node->str.no_free = true;

    // libblas.so.3 is needed by numpy
    node = pseudo_add_str(root, "libblas.so.3", &libblas);
    node->str.no_free = true;

    // libgcc_s.so.1 is needed by numpy
    node = pseudo_add_str(root, "libgcc_s.so.1", &libgcc_s);
    node->str.no_free = true;

    // liblapack.so.3 is needed by numpy
    node = pseudo_add_str(root, "liblapack.so.3", &liblapack);
    node->str.no_free = true;

    // libgfortran.so.5 is needed by numpy
    node = pseudo_add_str(root, "libgfortran.so.5", &libgfortran);
    node->str.no_free = true;

    // libffi.so.8 is needed by scipy
    node = pseudo_add_str(root, "libffi.so.8", &libffi);
    node->str.no_free = true;

    // libstdc++.so.6 is needed by scipy
    node = pseudo_add_str(root, "libstdc++.so.6", &libstdcpp);
    node->str.no_free = true;

    return 0;
}
