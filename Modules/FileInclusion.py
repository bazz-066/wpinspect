from core.modules import BaseClass
import copy

class FileInclusion(BaseClass):

    name = "File Inclusion"

    severity = "High"

    functions = [
        "include",
        "require",
        "include_once",
        "require_once"
    ]

    blacklist = [
        "sanitize_file_name"
    ]
