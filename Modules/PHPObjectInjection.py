from core.modules import BaseClass

class PHPObjectInjection(BaseClass):

    # Vulnerability name
    name = "PHP Object Injection"

    # Severity
    severity = "High"

    # Functions indicating vulnerability
    functions = [
        "unserialize",
        "maybe_unserialize"
    ]

    blacklist = []
