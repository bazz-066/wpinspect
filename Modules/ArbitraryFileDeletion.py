from core.modules import BaseClass

class ArbitraryFileDeletion(BaseClass):

    name = "Arbitrary File Deletion"

    severity = "Medium"

    functions = [
        "wp_delete_file",
        "unlink"
    ]

    blacklist = []
