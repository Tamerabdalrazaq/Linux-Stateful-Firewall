import sys
import os
sys.path.insert(1, os.path.abspath("../C_detector"))
import analyze_dlp

# Incoming  Singatures

def ofbiz_forgotpw(headers, body):
    headers = headers.split('\r\n')
    method, target, _v = headers[0].split(" ")
    if method == "POST" and "webtools/control/forgotpassword" in target.lower() and "/programexport" in target.lower():
        pairs = body.split("&")
        for pair in pairs:
            key, value = pair.split("=")
            if key.lower() == "groovyprogram":
                return (True, "400")
    return (False, "")


# Outgoing Signatures
def bad_length_and_encoding(headers, body):
    content_length = None
    content_encoding = None
    headers = headers.split("\r\n")
    for header in headers:
        if header.lower().startswith("content-length:"):
            content_length = int(header.split(":")[1].strip())
        elif header.lower().startswith("content-encoding:"):
            content_encoding = header.split(":")[1].strip().lower()
    # Block response based on criteria
    if (content_length is not None and content_length > 102400):
        reason = ("Blocking HTTP response: Content-Length is greater than 100KB")
        return (True, reason)  # Block the packet
    if (content_encoding == "gzip"):
        reason = ("Blocking HTTP response: Content-Encoding is GZIP.")
        return (True, reason)  # Block the packet
    return (False, "")

def data_leak(headers, body):
    score = analyze_dlp.get_snippet_score(body)
    print("DLP Score: ", score)
    if(score > analyze_dlp.THRESHOLD):
        return (True, "Data Leak Prevented")
    return (False, "")

HTTP_SIGNATURES_IN = [ofbiz_forgotpw]
HTTP_SIGNATURES_OUT = [bad_length_and_encoding, data_leak]