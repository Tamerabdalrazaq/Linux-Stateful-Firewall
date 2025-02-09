import math

THRESHOLD = 60
html_keywords = [
    # Common HTML tags
    "<html>", "</html>", "<head>", "</head>", "<title>", "</title>", 
    "<body>", "</body>", "<meta>", "<link>", "<script>", "</script>", 
    "<style>", "</style>", "<div>", "</div>", "<span>", "</span>", 
    "<p>", "</p>", "<a>", "</a>", "<img>", "<ul>", "</ul>", "<ol>", "</ol>", 
    "<li>", "</li>", "<table>", "</table>", "<tr>", "</tr>", "<td>", "</td>", 
    "<th>", "</th>", "<thead>", "</thead>", "<tbody>", "</tbody>", 
    "<tfoot>", "</tfoot>", "<form>", "</form>", "<input>", "<button>", "</button>", 
    "<label>", "</label>", "<select>", "</select>", "<option>", "</option>", 
    "<textarea>", "</textarea>", "<fieldset>", "</fieldset>", "<legend>", "</legend>", 
    "<iframe>", "</iframe>", "<canvas>", "</canvas>", "<svg>", "</svg>", 
    "<video>", "</video>", "<audio>", "</audio>", "<source>", "<track>", "<embed>", 
    "<object>", "</object>", "<picture>", "</picture>", "<figure>", "</figure>", 
    "<figcaption>", "</figcaption>", "<article>", "</article>", "<section>", "</section>", 
    "<nav>", "</nav>", "<aside>", "</aside>", "<header>", "</header>", "<footer>", "</footer>", 
    "<main>", "</main>", "<h1>", "</h1>", "<h2>", "</h2>", "<h3>", "</h3>", "<h4>", "</h4>", 
    "<h5>", "</h5>", "<h6>", "</h6>", "<strong>", "</strong>", "<em>", "</em>", 
    "<b>", "</b>", "<i>", "</i>", "<u>", "</u>", "<s>", "</s>", "<sub>", "</sub>", 
    "<sup>", "</sup>", "<code>", "</code>", "<pre>", "</pre>", "<blockquote>", "</blockquote>", 
    "<hr>", "<br>", "<wbr>", "<mark>", "</mark>", "<small>", "</small>", "<cite>", "</cite>", 
    "<abbr>", "</abbr>", "<time>", "</time>", "<data>", "</data>", "<progress>", "</progress>", 
    "<meter>", "</meter>", "<details>", "</details>", "<summary>", "</summary>", "<dialog>", "</dialog>", 
    "<template>", "</template>", "<slot>", "</slot>",

    # Unique HTML attributes (Not wrapped since they are not standalone tags)
    "href", "src", "alt", "id", "style", "title", "name", "value",
    "placeholder", "checked", "disabled", "readonly", "multiple", "required",
    "selected", "maxlength", "minlength", "pattern", "type", "action",
    "method", "target", "rel", "download", "enctype", "autocomplete",
    "autofocus", "novalidate", "form", "rows", "cols", "wrap",
    "min", "max", "step", "accept", "capture", "draggable",
    "contenteditable", "spellcheck", "translate", "hidden", "tabindex",
    "accesskey", "aria-label", "aria-hidden", "role", "part", "slot", 
    
    # HTML-specific values
    "submit", "reset", "button", "checkbox", "radio", "text", "password",
    "email", "url", "tel", "number", "search", "date", "datetime-local",
    "month", "week", "time", "color", "file", "_blank", "_self", "_parent",
    "_top", "noopener", "noreferrer", "manifest", "preload", "module"
]

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
    "->",  # Member Access Operators
    "(type)",  # Type Casting

    # Special Symbols
    "{", "}", "[", "]", "(", ")", ":", ";",

    # Escape Sequences
    "\\n", "\\t", "\\r", "\\b", "\\\\", "\\'", "\\\"", "\\0",

    # Function-Related Keywords
    "main()", "return", "void", 
        # Memory Management (stdlib.h)
    "malloc", "calloc", "realloc", "free",
    
    # Process and System Control (stdlib.h, unistd.h)
    "exit", "abort", "system", "_Exit", "getenv", "setenv",
    
    # File I/O (stdio.h)
    "fopen", "fclose", "fscanf", "fprintf", "fseek", "ftell", "fread", "fwrite",
    
    # String Manipulation (string.h)
    "strlen", "strcpy", "strncpy", "strcat", "strncat", "strcmp", "strchr", "strstr",
    
    # Math and Random (math.h, stdlib.h)
    "rand", "srand", "abs", "pow", "sqrt", "ceil", "floor", "sin", "cos", "tan",
    
    # Low-Level Memory and Byte Manipulation (string.h)
    "memcpy", "memmove", "memset", "memcmp",
    
    # Special Utility Functions (stdlib.h, ctype.h)
    "atoi", "atof", "qsort", "bsearch", "toupper", "tolower"

]

c_syntax_elements = sorted(c_syntax_elements, key=len, reverse=True)


c_distict_keywords = {
    "sizeof(": 10, 
    "printf(": 3, "malloc": 5, "NULL": 5, "stdlib": 5,
    "#define": 5, "#include": 5, "#if": 5, "#ifdef": 5, "#ifndef": 5, 
    "main()": 10, 
    "int*": 5, "char*": 5, "float*": 5, "double*": 5, "void*": 5, "short*": 5, "long*": 5,
    "void": 2,  "calloc(": 5, "realloc(": 5, "free(": 5,
    # String Manipulation (string.h)
    "strlen(": 2, "strcpy(": 2, "strncpy(": 2, "strcat(": 2, "strncat(": 2, "strcmp(": 2, "strchr(": 2, "strstr(": 2,
        
    # Low-Level Memory and Byte Manipulation (string.h)
    "memcpy(": 2, "memmove(": 2, "memset(": 2, "memcmp(": 2,
}

def cleanse_snippet(text):
    text = text.replace(" ", "").replace("\n", "").replace("\\n", "")
    for keyword in html_keywords:
        text = text.replace(keyword, " "*len(keyword))
    return text

def intensify_snippet(text):
    length = len(text)
    if length == 0: return text
    for keyword in c_distict_keywords.keys():
        facotr = 10 * int(math.log(length/len(keyword), 3))
        text = text.replace(keyword, keyword*facotr*(c_distict_keywords.get(keyword)))
    return text


def prep_snippet(text):
    return intensify_snippet(cleanse_snippet(text))
    
def get_snippet_score(snippet):
    snippet = prep_snippet(snippet)
    copy = str(snippet)
    for key in c_syntax_elements:
        copy = copy.replace(key, "")
    keys_raw_len = len(snippet) - len(copy)
    score = (keys_raw_len / float(len(snippet))) * 100
    return score