# test_final_pipeline.py
from url import (
    extract_urls_and_domains,
    normalize_full_url,
    is_blacklisted,
    get_db_connection,
    get_blacklist_connection
)
import logging

# ----------------------------
# Logger setup
# ----------------------------
logger = logging.getLogger("pipeline")
logging.basicConfig(level=logging.INFO)

# ----------------------------
# Analyze pipeline function
# ----------------------------
def analyze_pipeline(message: str):
    """Domain whitelist -> full-URL blacklist override -> return dict.
       Translation and language detection ignored."""
    try:
        text = (message or "").strip()
        if not text:
            return {"error": "empty", "blacklist": False}

        # Extract full URLs and domains
        full_urls, domains = extract_urls_and_domains(text)

        # Load whitelist
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT LOWER(domain) FROM whitelist")
            rows = cursor.fetchall()
            whitelist_set = {r[0] for r in rows if r and r[0]}
            conn.close()
        except Exception as e:
            logger.warning(f"Whitelist load failed: {e}")
            whitelist_set = set()

        # 1️⃣ Domain whitelist check (subdomains)
        if domains and whitelist_set:
            for domain in domains:
                d = (domain or "").lower().strip().strip('/')
                if not d:
                    continue
                matched_whitelist = d in whitelist_set or any(d.endswith("." + wl) for wl in whitelist_set)

                if matched_whitelist:
                    # Check full URL against blacklist
                    if full_urls:
                        try:
                            bconn = get_blacklist_connection()
                            bcur = bconn.cursor()
                            for u in full_urls:
                                norm_u = normalize_full_url(u).lower()
                                bcur.execute("SELECT 1 FROM blacklist WHERE LOWER(url) = ?", (norm_u,))
                                if bcur.fetchone():
                                    bconn.close()
                                    return {
                                        "result": "Phishing",
                                        "confidence": "100.0%",
                                        "message": text,
                                        "blacklist": True,
                                        "whitelist": False,
                                        "detected_lang": None,
                                        "translated_text": None
                                    }
                            bconn.close()
                        except Exception as e:
                            logger.warning(f"Blacklist-full-url check failed: {e}")

                    # Safe because domain is whitelisted
                    return {
                        "result": "Safe",
                        "confidence": "100.0%",
                        "message": text,
                        "blacklist": False,
                        "whitelist": True,
                        "detected_lang": None,
                        "translated_text": None
                    }

        # 2️⃣ Not whitelisted -> regular blacklist check
        is_black, reason = is_blacklisted(text)
        if is_black:
            return {
                "result": "Phishing",
                "confidence": "100.0%",
                "message": text,
                "blacklist": True,
                "whitelist": False,
                "detected_lang": None,
                "translated_text": None
            }

        # 3️⃣ If neither whitelisted nor blacklisted, mark as Safe
        return {
            "result": "Safe",
            "confidence": "100.0%",
            "message": text,
            "blacklist": False,
            "whitelist": False,
            "detected_lang": None,
            "translated_text": None
        }

    except Exception as e:
        logger.error(f"Pipeline error: {e}")
        return {
            "result": "Error",
            "confidence": "0%",
            "message": message,
            "blacklist": False,
            "whitelist": False,
            "detected_lang": None,
            "translated_text": None
        }

# ----------------------------
# Run pipeline on sample text
# ----------------------------
if __name__ == "__main__":
    sample_text = """
    https://docs.google.com/drawings/d/11IoUM6Kpsu2IZa4w3vpTI5E4i00-jxWYbU5DzFvp8Iw/edit
    """
    result = analyze_pipeline(sample_text)

    print("\n=== FINAL PIPELINE RESULT ===")
    for key, value in result.items():
        print(f"{key}: {value}")
