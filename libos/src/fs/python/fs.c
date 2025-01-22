#include "libos_fs.h"
#include "libos_fs_pseudo.h"
#include "perm.h"

#include "python.c"
#include "stdlib.c"
#include "cpuid_so.c"

// #include "dependencies_dynamic-html.c" // 23 -> 256 // python3 scripts/dependencies_zip_generator.py deps/110.dynamic-html_code/site-packages/ "libos/src/fs/python/dependencies_dynamic-html.c"
// #include "dependencies_thumbnailer.c" // 36 -> 256 // python3 scripts/dependencies_zip_generator.py deps/210.thumbnailer_code/site-packages/ "libos/src/fs/python/dependencies_thumbnailer.c"
#include "dependencies_image-recognition.c" // 1661 -> 2048 // python3 scripts/dependencies_zip_generator.py deps/411.image-recognition_code/site-packages/ "libos/src/fs/python/dependencies_image-recognition.c"
// #include "dependencies_igraph.c" // 81 -> 256 // python3 scripts/dependencies_zip_generator.py deps/501.graph-pagerank_code/site-packages/ "libos/src/fs/python/dependencies_igraph.c"
// #include "dependencies_dna-visualisation.c" // 124 -> 8192 // python3 scripts/dependencies_zip_generator.py deps/504.dna-visualisation_code/site-packages/ "libos/src/fs/python/dependencies_dna-visualisation.c"

/*
// for the 110.dynamic-html benchmark
#include "template.c"
*/


// for the 411.image-recognition benchmark
#include "imagenet_class_index.c"



static int python_bin(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) python;
    *out_size = python_len;
    return 0;
}

static int stdlib(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) python311_zip;
    *out_size = python311_zip_len;
    return 0;
}

static int cpuid__so(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) cpuid_so;
    *out_size = cpuid_so_len;
    return 0;
}


// for the 110.dynamic-html benchmark
/*
static int template(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) template_html;
    *out_size = template_html_len;
    return 0;
}
*/


// for the 411.image-recognition benchmark
static int imagenet_class_index(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    *out_data = (char*) imagenet_class_index_json;
    *out_size = imagenet_class_index_json_len;
    return 0;
}



int init_pythonfs(void) {
    struct pseudo_node* root = pseudo_add_root_dir("python");

    struct pseudo_node* node = pseudo_add_str(root, "python", &python_bin);
    node->str.no_free = true;
    node->perm = PERM_r_xr_xr_x;

    node = pseudo_add_str(root, "stdlib.zip", &stdlib);
    node->str.no_free = true;

    node = pseudo_add_str(root, "cpuid.so", &cpuid__so);
    node->str.no_free = true;

    init_dependencies(pseudo_add_dir(root, "dependencies"));

/*
    // for the 110.dynamic-html benchmark
    node = pseudo_add_str(root, "template.html", &template);
    node->str.no_free = true;
*/


    // for the 411.image-recognition benchmark
    node = pseudo_add_str(root, "imagenet_class_index.json", &imagenet_class_index);
    node->str.no_free = true;


    return 0;
}
