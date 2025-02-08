import math

THRESHOLD = 36.1335
c_syntax_elements = [
    #  General 
    "printf", "malloc", "NULL", "stdlib",
    # Control Flow Keywords
    "if", "else", "switch", "case", "default", "for", "while", "do",
    "break", "continue", "goto", "return",

    # Data Types & Type Modifiers
    "int", "char", "float", "double", "void", "short", "long",
    "signed", "unsigned",

    # Storage Class Specifiers
    "auto", "static", "extern", "register", "typedef",

    # Memory Management
    "sizeof", "alignof", "_Alignas", "_Alignof",

    # Structs, Unions, and Enums
    "struct", "union", "enum",

    # Function Specifiers
    "inline", "_Noreturn",

    # Preprocessor Directives
    "#define", "#include", "#if", "#ifdef", "#ifndef", "#else",
    "#elif", "#endif", "#pragma", "#error", "#warning", "#undef",
    "#line", "#file", "_Pragma",

    # Type Qualifiers
    "const", "volatile", "restrict", "_Atomic",

    # Boolean (C99+)
    "_Bool", "bool",

    # Threading (C11)
    "_Thread_local",

    # Complex Numbers (C99)
    "_Complex", "_Imaginary",

    # Operators
    "+", "-", "*", "/", "%", "++", "--",
    "==", "!=", ">", "<", ">=", "<=",
    "&&", "||", "!", "&", "|", "^", "~",
    "<<", ">>", "=", "+=", "-=", "*=", "/=", "%=",
    "&=", "|=", "^=", "<<=", ">>=",
    "?", ":",  # Ternary operator
    "*", "&",  # Pointer Operators
    ".", "->",  # Member Access Operators
    "(type)",  # Type Casting

    # Special Symbols
    "{", "}", "[", "]", "(", ")", ",", ":", ";",

    # Escape Sequences
    "\\n", "\\t", "\\r", "\\b", "\\\\", "\\'", "\\\"", "\\0",

    # Function-Related Keywords
    "main()", "return", "void", 

]

def cleanse_snippet(text):
    return text.replace(" ", "").replace("\n", "").replace("\\n", "")

def get_snippet_score(snippet):
    snippet = cleanse_snippet(snippet)
    copy = str(snippet)
    for key in c_syntax_elements:
        copy = copy.replace(key, "")
    keys_raw_len = len(snippet) - len(copy)
    score = (keys_raw_len / float(len(snippet))) * 100
    return score