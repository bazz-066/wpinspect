from core.modules import BaseClass

class PathTraversal(BaseClass):

    name = "Directory Traversal"

    severity = "High"

    functions = [
        "file",
        "readfile",
        "fopen",
        "fread",
        "file_get_contents"
    ]

    blacklist = [
        "sanitize_file_name"
    ]
