from core.modules import BaseClass

class CommandInjection(BaseClass):

    name = "Command Injection"

    severity = "High"

    functions = [
        "eval",
        "popen",
        "assert",
        "system",
        "passthru",
        "exec",
        "shell_exec",
        "proc_open"
    ]

    blacklist = [
        "escapeshellcmd",
        "escapeshellarg"
    ]