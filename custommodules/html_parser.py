import html.parser

try:
    HTMLParseError = html.parser.HTMLParseError
except AttributeError:
    # create a dummy class for Python 3.5+ where it's been removed
    class HTMLParseError(Exception):
        pass
