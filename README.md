# wpInspect [![Python 2.x|3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/)
wpInspect is a tool for static code analysis on WordPress plugins and wordpress themes developed from OWASP's wpBullet tool

## Installation
Simply clone the repository, install requirements and run the script 
- `$ git clone https://github.com/bazz-066/wpinspect` 
- `$ cd wpinspect`
- `$ pip install -r requirements.txt`
- `$ python3 wpinspect.py`


## Usage
Available options:

* `--path` option

    To determine the WordPress plugins or themes that will be scanned

    There are 3 ways to determine which plugins / themes to check:

    ```
    --path="/path/to/plugin"
    --path="https://wordpress.org/plugins/example-plugin"
    --path="https://downloads.wordpress.org/plugin/example-plugin.1.5.zip"
    ```

    Example:

    ```
    $ python3 wpinspect.py --path="/var/www/wp-content/plugins/plugin-name"
    ```

* `--enabled` option (Optional)

    Check only for given modules

    Example:

    ```
    $ python3 wpinspect.py --path="/var/www/wp-content/plugins/plugin-name" --enabled="OpenRedirect"
    ```

* `--disabled` option (Optional)

    Don't check for given modules

    Example:

    ```
    $ python3 wpinspect.py --path="/var/www/wp-content/plugins/plugin-name" --disabled="OpenRedirect"
    ```

* `--cleanup` option (Optional)

    Automatically remove content of `.temp`` folder after scanning remotely downloaded plugin

    Example:

    ```
    $ python3 wpinspect.py --path="/var/www/wp-content/plugins/plugin-name" --cleanup 1
    ```

* `--report` option (Optional)

    Saves result inside `reports/`` directory in JSON format

    Example:

    ```
    $ python3 wpinspect.py --path="/var/www/wp-content/plugins/plugin-name" --report 1
    ```

## Modules
The modules in wpInspect are flexible components that allow users to create their own detection rules for security vulnerabilities in WordPress plugins and themes. The modules in wpInspect are designed to be user-friendly and enable users to create their own modules to detect vulnerabilities in WordPress plugins or themes.

### Module template

`Modules/ExampleVulnerability.py`
```python
from core.modules import BaseClass

class ExampleVulnerability(object):

    # Vulnerability name
    name = "Cross-site Scripting"

    # Vulnerability severity
    severity = "Low-Medium"

    # Functions causing vulnerability
    functions = [
        "print"
        "echo"
    ]

    # Functions/regex that prevent exploitation
    blacklist = [
        "htmlspecialchars",
        "esc_attr"
    ]

```

### Overriding regex match pattern
Regex pattern is being generated in `core.modules.BaseClass.build_pattern` and therefore can be overwritten in 
each module class.

`Modules/ExampleVulnerability.py`
```python
import copy

...
# Build dynamic regex pattern to locate vulnerabilities in given content
def build_pattern(self, content, file):
    user_input = copy.deepcopy(self.user_input)

    variables = self.get_input_variables(self, content)

    if variables:
        user_input.extend(variables)

    if self.blacklist:
        blacklist_pattern = r"(?!(\s?)+(.*(" + '|'.join(self.blacklist) + ")))"
    else:
        blacklist_pattern = ""

    self.functions = [self.functions_prefix + x for x in self.functions]

    pattern = r"((" + '|'.join(self.functions) + ")\s{0,}\(?\s{0,1}" + blacklist_pattern + ".*(" + '|'.join(user_input) + ").*)"
    return pattern
```

## Testing
Running unit tests: `$ python3 -m unittest`

## References
* https://www.wordfence.com/wp-content/uploads/2021/07/Common-WordPress-Vulnerabilities-and-Prevention-Through-Secure-Coding-Best-Practices.pdf
* https://wpscan.com/howto-find-wordpress-plugin-vulnerabilities-wpscan-ebook.pdf