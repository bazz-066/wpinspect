import re
import copy
from core import scanner

class BaseClass(object):

    # Vulnerability name
    name = ""

    # Vulnerability severity
    severity = ""

    # Functions causing vulnerability
    functions = []

    # Prefix before function causing vulnerability
    # (?<![^\s+(]) - negative lookahead allows only <nothing>, space and open brackets
    functions_prefix = r"(?<![^\s+(])"

    # Functions/regex that prevent exploitation
    blacklist = []

    # User-controlled variables
    user_input = [
        "\\$_GET\\[",
        "\\$_POST\\[",
        "\\$_REQUEST\\[",
        "\\$_FILES\\[",
        "\\$_COOKIE\\[",
        "\\$_SERVER(\\s?)\\[(\\s?)+('|\\\"|`)(REQUEST_URI|PHP_SELF|HTTP_REFERER)(\\s?)+('|\\\"|`)(\\s?)+]",
        "\\$_SESSION\\["
    ]

    # Finds vulnerabilities in given file content
    def run(self, content, file):
        pattern = self.build_pattern(self, content=content, file=file)
        matches = re.findall(pattern=pattern, string=content)
        return matches

    # Prints all found vulnerabilities
    def execute(self, content, file):
        matches = self.run(self, content, file)
        for match in matches:
            if match[0]:
                scanner.CODE_VULNERABILITIES.append([self.severity, self.name, file + ":" + str(self.get_match_line(content, match[0])), match[0] ])

    # Build dynamic regex pattern to locate vulnerabilities in given content
    def build_pattern(self, content, file):
        user_input = copy.deepcopy(self.user_input)
        functions = copy.deepcopy(self.functions)

        variables = self.get_input_variables(self, content)

        ## Exact match
        variables = [element + r'(?!\w)' for element in variables]

        if variables:
            user_input.extend(variables)

        if self.blacklist:
            blacklist_pattern = r"(?!(\s?)+(.*(" + '|'.join(self.blacklist) + ")))"
        else:
            blacklist_pattern = ""

        functions = [self.functions_prefix + x for x in functions]

        pattern = r"((" + '|'.join(functions) + ")\s{0,}\(\s{0,}" + blacklist_pattern + ".*(" + '|'.join(user_input) + ").*)"
        return pattern

    # Finds line in file on which vulnerability occurs
    @staticmethod
    def get_match_line(content, match):
        lineNo = 0
        for line in content.split('\n'):
            lineNo = lineNo + 1
            if match in line:
                return lineNo
        return False

    # To prevent catastrophic backtracking because of a very long arr (ex: typography.php, fungsi generate_get_all_google_fonts)
    def remove_long_arr(content):
        # Find all arr in the content
        arr = re.findall(r'\[.*\]', content)

        # If there are no arr in the content, return it unchanged
        if not arr:
            return content

        # Loop over each JSON object and remove it if it exceeds the maximum length
        for arr_res in arr:
            if len(arr_res) > 10000:
                content = content.replace(arr_res, '')

        return content

    # To prevent catastrophic backtracking because of a very long json (ex: class-languages.php, fungsi get_wp_languages_backup)
    def remove_long_json(content):
        # Find all JSON objects in the content
        json_objects = re.findall(r'{.*}', content)

        # If there are no JSON objects in the content, return it unchanged
        if not json_objects:
            return content

        # Loop over each JSON object and remove it if it exceeds the maximum length
        for json_obj in json_objects:
            if len(json_obj) > 10000:
                content = content.replace(json_obj, '')

        return content

    # Get variables which's content is possible to manipulate with user input
    def get_input_variables(self, content):
        if self.blacklist:
            blacklist_pattern = r"(?!(\s?)+(.*(" + '|'.join(self.blacklist) + ")))"
        else:
            blacklist_pattern = ""

        user_controlled = "(" + '|'.join(self.user_input) +")"

        content = self.remove_long_json(content)
        content = self.remove_long_arr(content)

        # print(content)

        if (re.search(user_controlled, content)):
            pattern = re.compile(blacklist_pattern + "((\$[a-zA-Z0-9-_.$]+)(\s?)+=(\s?)+).*(" + '|'.join(self.user_input) +")", flags=re.IGNORECASE)
            # print(blacklist_pattern + "((\$[a-zA-Z0-9-_.$]+)(\s?)+=(\s?)+).*(" + '|'.join(self.user_input) +")")
            matches = re.findall(pattern=pattern, string=content)

            # Remove empty tuples
            matches = [tuple(filter(lambda x: x != '', t)) for t in matches]

            variables = []
            for match in matches:
                variables.append(re.escape(match[1]))
            
            # print(variables)

            return list(dict.fromkeys(variables))
        else:
            return []
