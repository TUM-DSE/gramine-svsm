import sys
import os

from jinja2 import Template

def generate_embedded_files_with_templates(folder_path, output_c_file):
    files = []
    dirs = []
    root_node = "root"

    for root, subdirs, filenames in os.walk(folder_path):
        subdirs[:] = [d for d in subdirs if os.listdir(os.path.join(root, d))]

        rel_root = os.path.relpath(root, folder_path)
        parent_node = root_node if rel_root == "." else "_".join(rel_root.split(os.sep)).replace(".", "_").replace("-", "_")

        for subdir in subdirs:
            dir_node_name = "_".join(os.path.relpath(os.path.join(root, subdir), folder_path).split(os.sep)).replace(".", "_").replace("-", "_")
            dirs.append({"node_name": dir_node_name, "parent_node": parent_node, "name": subdir})

        for filename in filenames:
            file_path = os.path.join(root, filename)
            var_name = "_".join(os.path.relpath(file_path, folder_path).split(os.sep)).replace(".", "_").replace("-", "_")
            writer_name = f"{var_name}_writer"

            with open(file_path, "rb") as f:
                data = f.read()

            byte_array = ", ".join(f"0x{byte:02x}" for byte in data)
            files.append({
                "var_name": var_name,
                "byte_array": byte_array,
                "length": len(data),
                "writer_name": writer_name,
                "parent_node": parent_node,
                "name": filename,
            })

    with open(os.path.join(os.path.dirname(__file__), "embedded_dependencies.c.j2")) as template_file:
        template = Template(template_file.read())
    with open(output_c_file, "w") as output_file:
        output_file.write(template.render(files=files, dirs=dirs))

if __name__ == "__main__":
    folder_path = sys.argv[1]
    output_c_file = sys.argv[2]
    generate_embedded_files_with_templates(folder_path, output_c_file)
    print(f"Generated {output_c_file}")
