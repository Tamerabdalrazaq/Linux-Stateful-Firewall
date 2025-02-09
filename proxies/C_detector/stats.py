import numpy as np
import matplotlib.pyplot as plt
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

def main():
    scores_text = analyze_normal_text()
    scores_html = analyze_html_text()
    scores_js = analyze_js_text()
    scores_c = analyze_c_code()

    plot_scores(scores_c, scores_text, scores_html, scores_js) 
    # plot_scores(scores_c)

def analyze_content(content, seperator):
    snippets = (get_snippets_array(content, seperator))
    cleansed_snippets = list(map(lambda txt: prep_snippet(txt), snippets))
    scores = analyze_snippets(cleansed_snippets)
    sorted_scores = sorted(scores)
    pure_scores = cleanse_repititions(sorted_scores)
    pure_scores = list(map(lambda x: round(x, 4), pure_scores))
    print(pure_scores, len(pure_scores), len(scores))
    return pure_scores


def analyze_normal_text():
    file1 = open("normal_text_sample.txt", "r")
    content = file1.read()
    pure_scores = analyze_content(content, "---")
    return pure_scores

def analyze_html_text():
    file1 = open("html_text_sample.txt", "r")
    content = file1.read()
    pure_scores = analyze_content(content, ".---.")
    return pure_scores

def analyze_js_text():
    file1 = open("js_code_sample.txt", "r")
    content = file1.read()
    pure_scores = analyze_content(content, ".---.")
    return pure_scores


def analyze_c_code():
    # global THRESHOLD
    file1 = open("c_code_dataset.txt", "r")
    file2 = open("c_code_dataset_long1.txt", "r")
    file3 = open("c_code_dataset_long2.txt", "r")
    file4 = open("kaggle_c_dataset.txt", "r")
    file5 = open("complex_c_dataset.txt", "r")
    content = file1.read() + file2.read() + file3.read() + file4.read() + file5.read()
    pure_scores = analyze_content(content, "#include <stdio.h>")
    fifth_percentile = int(0.05 * len(pure_scores))
    # THRESHOLD = pure_scores[fifth_percentile]
    print("\navg: ", sum(pure_scores)/len(pure_scores))
    print(THRESHOLD, fifth_percentile)
    return pure_scores

def cleanse_repititions(sorted_arr):
    cleansed = []
    cleansed.append(sorted_arr[0])
    for i in range(1, len(sorted_arr)):
        if sorted_arr[i] != sorted_arr[i-1]:
            cleansed.append(sorted_arr[i])
    return cleansed

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

def get_snippet_score(snippet):
    copy = str(snippet)
    for key in c_syntax_elements:
        copy = copy.replace(key, "")
    keys_raw_len = len(snippet) - len(copy)
    score = (keys_raw_len / float(len(snippet))) * 100
    return score

def prep_snippet(text):
    return intensify_snippet(cleanse_snippet(text))



def analyze_snippets(snippets):
    scores = []
    for snippet in snippets:
        if len(snippet) > 0:
            scores.append(get_snippet_score(snippet))
    return scores

def get_snippets_array(code, seperator):
    arr = code.split(seperator)
    arr = [snip for snip in arr if len(snip) > 0]
    return arr

def plot_scores(scores1, scores2=[], scores3 = [], scores4 = []):
    # Compute CDF for scores1
    scores1 = np.sort(scores1)
    cdf1 = np.arange(1, len(scores1) + 1) / len(scores1)
    
    # Compute CDF for scores2
    scores2 = np.sort(scores2)
    cdf2 = np.arange(1, len(scores2) + 1) / len(scores2)

    scores3 = np.sort(scores3)
    cdf3 = np.arange(1, len(scores3) + 1) / len(scores3)

    scores4 = np.sort(scores4)
    cdf4 = np.arange(1, len(scores4) + 1) / len(scores4)

    # Plot the CDFs
    plt.figure(figsize=(10, 5))
    plt.plot(scores1, cdf1, marker=".", linestyle="-", color="b", label="CDF - 226 C snippets")
    plt.plot(scores2, cdf2, marker=".", linestyle="-", color="#129fa1", label="CDF - 80 text samples")
    plt.plot(scores3, cdf3, marker=".", linestyle="-", color="#E34F26", label="CDF - HTML")
    plt.plot(scores4, cdf4, marker=".", linestyle="-", color="#F7DF1E", label="CDF - Javascript")

    plt.axvline(x=THRESHOLD, color='g', linestyle='--', label='Verdict Threshold (5-th percentile)')

    # Labels and title
    plt.xlabel("Score")
    plt.ylabel("Cumulative Probability")
    plt.title("Comparison of CDFs for C code (blue) and other text")
    plt.grid(linestyle="--", alpha=1)
    plt.legend()

    # Show the chart
    plt.show()


main()