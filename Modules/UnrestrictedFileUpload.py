from core.modules import BaseClass

class UnrestrictedFileUpload(BaseClass):

    name = "Unrestricted File Upload"

    severity = "High"

    functions = [
        "file_put_contents",
        "fwrite",
        "move_uploaded_file"
    ]

    blacklist = [
        "wp_check_filetype_and_ext",
        "wp_check_filetype",
        "wp_handle_upload"
    ]
