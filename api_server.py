from fastapi import FastAPI, Query

from osiris.search_links import generate_search_links
from osiris.threat_scoring import score_threat

app = FastAPI()

@app.get("/search/")
def search(target: str = Query(...), category: str = Query(None)):
    results = generate_search_links(target, category)
    enriched = []

    for r in results:
        threat = score_threat(r, target)
        enriched.append({
            "url": r,
            "score": threat["score"],
            "label": threat["label"],
            "reasons": threat["reasons"]
        })

    return {"target": target, "results": enriched}
