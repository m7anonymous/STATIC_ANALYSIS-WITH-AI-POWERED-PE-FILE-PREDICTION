import xml.etree.ElementTree as ET


XML_PATH = "rules/heuristic_keywords.xml"

def load_keywords():

    try:

        tree = ET.parse(XML_PATH)

        root = tree.getroot()

        keywords = []

        for item in root.findall("keyword"):

            keyword_data = {
                "text": item.text.lower(),
                "score": int(item.get("score"))
            }

            keywords.append(keyword_data)

        return keywords

    except Exception as e:
        print(f"[ERROR] Failed to load XML: {e}")
        return []

def heuristic_scan(file_path):

    try:

        keywords = load_keywords()

        with open(file_path, "r", errors="ignore") as f:
            content = f.read().lower()

        matched_keywords = []

        total_score = 0

        for keyword in keywords:

            if keyword["text"] in content:

                matched_keywords.append(keyword)

                total_score += keyword["score"]

        return matched_keywords, total_score

    except Exception as e:
        print(f"[ERROR] Heuristic scan failed: {e}")
        return [], 0
