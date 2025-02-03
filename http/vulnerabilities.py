def ofbiz_forgotpw(headers, body):
    headers = headers.split('\r\n')
    method, target, _v = headers[0].split(" ")
    if method == "POST" and "webtools/control/forgotpassword" in target.lower() and "/programexport" in target.lower:
        pairs = body.split("&")
        for pair in pairs:
            key, value = pair.split("=")
            if key.lower() == "groovyprogram":
                return True
    return False


HTTP_SIGNATURES = [ofbiz_forgotpw]