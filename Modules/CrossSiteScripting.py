from core.modules import BaseClass
import copy

class CrossSiteScripting(BaseClass):

    name = "Cross site scripting"

    severity = "Medium"

    functions = [
        "print",
        "echo",
        "printf"
    ]

    blacklist = [
        "htmlspecialchars",
        "htmlentities",
        "sanitize_text_field",
        "sanitize_email",
        "sanitize_file_name",
        "sanitize_html_class",
        "sanitize_key",
        "sanitize_meta",
        "sanitize_mime_type",
        "sanitize_option",
        "sanitize_title",
        "sanitize_title_for_query",
        "sanitize_title_with_dashes",
        "sanitize_user",
        "esc_attr",
        "esc_html",
        "esc_js",
        "esc_textarea",
        "esc_url",
        "esc_url_raw",
        "wp_kses_data",
        "wp_kses_post",
        "wp_kses",
        "absint",
        "abs",
        "intval",
        "int",
        "floatval",
        "float"
    ]

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

        pattern = r"((" + '|'.join(functions) + ")\s{0,}\(?\s{0,1}" + blacklist_pattern + ".*(" + '|'.join(user_input) + ").*)"
        return pattern
