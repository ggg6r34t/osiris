def parse_input(platforms):
    """
    Normalize an input list. If no platforms are provided, default to all.
    """
    if not platforms:
        return ["all"]
    normalized = [p.strip().lower() for p in platforms if str(p).strip()]
    return list(dict.fromkeys(normalized))
