# Lots of security + vibe issues

API_KEY = "sk_live_1234567890abcdef"  # hardcoded secret

def f(a,b,c): return a+b+c  # single-letter args, one-liner

x = eval("2 + 2")  # insecure-eval
exec("print('hi')")  # insecure-exec

def do_stuff(data):
    l = [1,2,3]  # ambiguous variable name
    result = data.strip().replace(" ","").split(",").join(",")  # weird chain
    return result

а = 10  # Cyrillic a (unicode-homoglyph)
