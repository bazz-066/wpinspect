from core.modules import BaseClass

class OpenRedirect(BaseClass):

    name = "Open Redirect"

    severity = "Low"

    functions = [
        "wp_redirect"
    ]

    blacklist = []
