"""Reverse-image web scan MVP (SerpApi Google Lens).

Thin wrapper around scanner.search_web_for_matches, which adds timeouts, a public-URL
check, key-safe error messages and result filtering.
"""

try:
    from dotenv import load_dotenv
    load_dotenv()  # read SERPAPI_KEY from a local .env file if present
except ImportError:
    pass  # python-dotenv is optional; SERPAPI_KEY can come from the real environment

from scanner import search_web_for_matches


def check_image_on_web(image_url: str, api_key: str | None = None) -> list:
    """Return [{"title", "url", "source"}] for visual matches of a public image URL."""
    print(f"Scanning the web for unauthorized matches of: {image_url}...")
    return search_web_for_matches(image_url, api_key)


if __name__ == "__main__":
    test_image_url = "https://images.unsplash.com/photo-1505740420928-5e560c06d30e"

    try:
        results = check_image_on_web(test_image_url)
        print(f"\nScan complete! Found {len(results)} potential matches online:")
        for item in results[:5]:
            print(f"- {item['title']}: {item['url']}")
    except Exception as e:
        print(f"Error during scan: {e}")
