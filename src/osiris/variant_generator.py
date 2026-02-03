def generate_typosquatting_domains(domain):
    parts = domain.split(".")
    if len(parts) >= 2:
        base, tld = domain.rsplit(".", 1)
    else:
        base, tld = domain, "com"
    subs = {
        'a': ['a', '4', '@'],
        'e': ['e', '3'],
        'i': ['i', '1', '!'],
        'o': ['o', '0'],
        'l': ['l', '1', '|'],
        's': ['s', '$', '5'],
        't': ['t', '7'],
    }

    variants = set()

    for i, c in enumerate(base):
        if c in subs:
            for s in subs[c]:
                variant = base[:i] + s + base[i+1:]
                variants.add(variant)

    for omission in range(len(base)):
        variant = base[:omission] + base[omission+1:]
        variants.add(variant)

    for i in range(len(base)):
        variant = base[:i] + base[i] + base[i:]  # repeated char
        variants.add(variant)

    return [f"{v}.{tld}" for v in variants if v != base]
