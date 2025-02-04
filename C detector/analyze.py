import numpy as np
import matplotlib.pyplot as plt
import math

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


def main():
    scores_c = analyze_c_code()
    scores_text = analyze_normal_text()
    plot_scores(scores_c, scores_text)

def analyze_content(content, seperator):
    snippets = (get_snippets_array(content, seperator))
    cleansed_snippets = list(map(lambda txt: cleanse_snippet(txt), snippets))
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


def analyze_c_code():
    file1 = open("c_code_dataset.txt", "r")
    file2 = open("c_code_dataset_long1.txt", "r")
    file3 = open("c_code_dataset_long2.txt", "r")
    file4 = open("kaggle_c_dataset.txt", "r")
    content = file1.read() + file2.read() + file3.read() + file4.read()
    pure_scores = analyze_content(content, "#include <stdio.h>")
    fifth_percentile = int(0.05 * len(pure_scores))
    print("\nThreshold:")
    print(pure_scores[fifth_percentile], fifth_percentile)
    return pure_scores

def cleanse_repititions(sorted_arr):
    cleansed = []
    cleansed.append(sorted_arr[0])
    for i in range(1, len(sorted_arr)):
        if sorted_arr[i] != sorted_arr[i-1]:
            cleansed.append(sorted_arr[i])
    return cleansed

def cleanse_snippet(text):
    return text.replace(" ", "").replace("\n", "").replace("\\n", "")

def get_snippet_score(snippet):
    copy = str(snippet)
    for key in c_syntax_elements:
        copy = copy.replace(key, "")
    keys_raw_len = len(snippet) - len(copy)
    score = (keys_raw_len / float(len(snippet))) * 100
    if score < 35 or score > 65:
        print(f"\n\n {copy} \n {snippet}\nscore: {score}\n")
    return score

def analyze_snippets(snippets):
    scores = []
    for snippet in snippets:
        if len(snippet) > 0:
            scores.append(get_snippet_score(snippet))
    return scores

def get_snippets_array(code, seperator):
    arr = code.split(seperator)
    return arr

def plot_scores(scores1, scores2=[]):
    # Compute CDF for scores1
    scores1 = np.sort(scores1)
    cdf1 = np.arange(1, len(scores1) + 1) / len(scores1)
    
    # Compute CDF for scores2
    scores2 = np.sort(scores2)
    cdf2 = np.arange(1, len(scores2) + 1) / len(scores2)

    # Plot the CDFs
    plt.figure(figsize=(10, 5))
    plt.plot(scores1, cdf1, marker=".", linestyle="-", color="b", label="CDF - 208 C snippets")
    plt.plot(scores2, cdf2, marker=".", linestyle="-", color="r", label="CDF - 80 text samples")

    plt.axvline(x=36.1335, color='g', linestyle='--', label='Verdict Threshold (5-th percentile)')

    # Labels and title
    plt.xlabel("Score")
    plt.ylabel("Cumulative Probability")
    plt.title("Comparison of CDFs for C code (blue) and normal text (red)")
    plt.grid(linestyle="--", alpha=1)
    plt.legend()

    # Show the chart
    plt.show()


main()