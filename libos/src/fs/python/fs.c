#include "libos_fs.h"
#include "libos_fs_pseudo.h"
#include "perm.h"

#include "python.c"
#include "stdlib.c"

// needs file // #include "dependencies_dynamic-html.c" // 49 -> ??? // python3 scripts/dependencies_zip_generator.py deps/110.dynamic-html_code/site-packages/ "libos/src/fs/python/dependencies_dynamic-html.c"
#include "dependencies_thumbnailer.c" // 137 -> 256 // python3 scripts/dependencies_zip_generator.py deps/210.thumbnailer_code/site-packages/ "libos/src/fs/python/dependencies_thumbnailer.c"
// needs file // #include "dependencies_image-recognition.c" // 12474 -> ??? // python3 scripts/dependencies_zip_generator.py deps/411.image-recognition_code/site-packages/ "libos/src/fs/python/dependencies_image-recognition.c"
// #include "dependencies_igraph.c" // 111 -> 256 // python3 scripts/dependencies_zip_generator.py deps/501.graph-pagerank_code/site-packages/ "libos/src/fs/python/dependencies_igraph.c"
// #include "dependencies_dna-visualisation.c" // 6016 -> 8192 // python3 scripts/dependencies_zip_generator.py deps/504.dna-visualisation_code/site-packages/ "libos/src/fs/python/dependencies_dna-visualisation.c"

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


int init_pythonfs(void) {
    struct pseudo_node* root = pseudo_add_root_dir("python");

    struct pseudo_node* node = pseudo_add_str(root, "python", &python_bin);
    node->str.no_free = true;
    node->perm = PERM_r_xr_xr_x;

    node = pseudo_add_str(root, "stdlib.zip", &stdlib);
    node->str.no_free = true;

    init_dependencies(pseudo_add_dir(root, "dependencies"));

    return 0;
}
