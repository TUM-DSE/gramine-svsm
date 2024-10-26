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
#include "libcrypt.c"
#include "libpthread.c"
#include "libdl.c"
#include "librt.c"
#include "libutil.c"
#include "libuuid.c"
#include "libbz2.c"
#include "libgdbm.c"
#include "libgdbm_compat.c"
#include "libssl.c"
#include "libcrypto.c"
#include "liblzma.c"
#include "libsqlite3.c"

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

static int libcrypt(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libcrypt_so_1;
    *out_size = libcrypt_so_1_len;
    return 0;
}

static int libpthread(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libpthread_so_0;
    *out_size = libpthread_so_0_len;
    return 0;
}

static int libdl(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libdl_so_2;
    *out_size = libdl_so_2_len;
    return 0;
}

static int librt(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) librt_so_1;
    *out_size = librt_so_1_len;
    return 0;
}

static int libutil(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libutil_so_1;
    *out_size = libutil_so_1_len;
    return 0;
}

static int libuuid(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libuuid_so_1;
    *out_size = libuuid_so_1_len;
    return 0;
}

static int libbz2(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libbz2_so_1_0;
    *out_size = libbz2_so_1_0_len;
    return 0;
}

static int libgdbm(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libgdbm_so_6;
    *out_size = libgdbm_so_6_len;
    return 0;
}

static int libgdbm_compat(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libgdbm_compat_so_4;
    *out_size = libgdbm_compat_so_4_len;
    return 0;
}

static int libssl(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libssl_so_3;
    *out_size = libssl_so_3_len;
    return 0;
}

static int libcrypto(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libcrypto_so_3;
    *out_size = libcrypto_so_3_len;
    return 0;
}

static int liblzma(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) liblzma_so_5;
    *out_size = liblzma_so_5_len;
    return 0;
}

static int libsqlite3(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) libsqlite3_so_0;
    *out_size = libsqlite3_so_0_len;
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

    // libblas.so.3 is needed by numpy?
    node = pseudo_add_str(root, "libblas.so.3", &libblas);
    node->str.no_free = true;

    // libgcc_s.so.1 is needed by numpy?
    node = pseudo_add_str(root, "libgcc_s.so.1", &libgcc_s);
    node->str.no_free = true;

    // liblapack.so.3 is needed by numpy?
    node = pseudo_add_str(root, "liblapack.so.3", &liblapack);
    node->str.no_free = true;

    // libgfortran.so.5 is needed by numpy?
    node = pseudo_add_str(root, "libgfortran.so.5", &libgfortran);
    node->str.no_free = true;

    // libffi.so.8 is needed by python
    node = pseudo_add_str(root, "libffi.so.8", &libffi);
    node->str.no_free = true;

    // libstdc++.so.6 is needed by scipy?
    node = pseudo_add_str(root, "libstdc++.so.6", &libstdcpp);
    node->str.no_free = true;

    // libcrypt.so.1 is needed for python?
    node = pseudo_add_str(root, "libcrypt.so.1", &libcrypt);
    node->str.no_free = true;

    // libpthread.so.0 is needed for python?
    node = pseudo_add_str(root, "libpthread.so.0", &libpthread);
    node->str.no_free = true;

    // libdl.so.2 is needed for python?
    node = pseudo_add_str(root, "libdl.so.2", &libdl);
    node->str.no_free = true;

    // librt.so.1 is needed for python?
    node = pseudo_add_str(root, "librt.so.1", &librt);
    node->str.no_free = true;

    // libutil.so.1 is needed for python?
    node = pseudo_add_str(root, "libutil.so.1", &libutil);
    node->str.no_free = true;

    // libuuid.so.1 is needed for python
    node = pseudo_add_str(root, "libuuid.so.1", &libuuid);
    node->str.no_free = true;

    // libbz2.so.1.0 is needed for python
    node = pseudo_add_str(root, "libbz2.so.1.0", &libbz2);
    node->str.no_free = true;

    // libgdbm.so.6 is needed for python
    node = pseudo_add_str(root, "libgdbm.so.6", &libgdbm);
    node->str.no_free = true;

    // libgdbm_compat.so.4 is needed for python
    node = pseudo_add_str(root, "libgdbm_compat.so.4", &libgdbm_compat);
    node->str.no_free = true;

    // libssl.so.3 is needed for python
    node = pseudo_add_str(root, "libssl.so.3", &libssl);
    node->str.no_free = true;

    // libcrypto.so.3 is needed for python
    node = pseudo_add_str(root, "libcrypto.so.3", &libcrypto);
    node->str.no_free = true;

    // liblzma.so.5 is needed for python
    node = pseudo_add_str(root, "liblzma.so.5", &liblzma);
    node->str.no_free = true;

    // libsqlite3.so.0 is needed for python
    node = pseudo_add_str(root, "libsqlite3.so.0", &libsqlite3);
    node->str.no_free = true;

    return 0;
}
