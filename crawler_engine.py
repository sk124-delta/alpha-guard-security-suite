"""Candidate discovery for reverse-image web scans.

Wraps scanner.search_web_for_matches (timeouts, public-URL checks, key-safe errors).
Results are unverified candidates: they carry no match score. Confirm a real match with
scanner.compute_image_hash / compare_hashes before creating any DMCA notice.
"""

from pathlib import Path

from dotenv import load_dotenv

from scanner import search_web_for_matches

load_dotenv(Path(__file__).with_name(".env"))


class WebCrawlerEngine:
    def __init__(self, api_key: str | None = None, max_results: int = 20):
        self.api_key = api_key
        self.max_results = max_results

    def search_by_image_url(self, image_url: str) -> list[dict]:
        """Return unverified candidate pages hosting visually similar images.

        Raises ValueError for a bad URL or missing SERPAPI_KEY and RuntimeError for
        search failures, rather than returning fabricated results.
        """
        matches = search_web_for_matches(image_url, self.api_key, self.max_results)
        return [
            {
                "infringing_url": match["url"],
                "title": match["title"],
                "source": match["source"],
                "host_abuse_email": None,
                "match_score": None,
            }
            for match in matches
        ]


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        raise SystemExit("Usage: python crawler_engine.py <public_image_url>")
    try:
        candidates = WebCrawlerEngine().search_by_image_url(sys.argv[1])
    except (ValueError, RuntimeError) as exc:
        raise SystemExit(f"Search failed: {exc}")
    print(f"[*] {len(candidates)} unverified candidates found:")
    for candidate in candidates:
        print(f"- {candidate['title']}: {candidate['infringing_url']}")
