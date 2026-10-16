from core.config import Config

LABELS = {
    "daily": "ប្រចាំថ្ងៃ",
    "weekly": "ប្រចាំសប្ដាហ៍",
    "monthly": "ប្រចាំខែ",
    "quarter": "៣ ខែ",
    "yearly": "ប្រចាំឆ្នាំ",
}

def all_plans():
    out = []
    for key, info in Config.PLANS.items():
        out.append({
            "key": key,
            "label": LABELS.get(key, key),
            "days": info["days"],
            "price": info["price"],
        })
    return out

def get_plan(key: str):
    info = Config.PLANS.get(key)
    if not info:
        return None
    return {
        "key": key,
        "label": LABELS.get(key, key),
        "days": info["days"],
        "price": info["price"],
    }
