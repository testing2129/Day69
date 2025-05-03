import requests
from bs4 import BeautifulSoup
import re
from typing import List, Dict

HN_API_BASE = "https://hacker-news.firebaseio.com/v0"
TIMEOUT = 10


class Post:
    def __init__(self, title: str, link: str, upvotes: int, author: str = "Unknown", content: str = ""):
        """Initializes a Post object."""
        self.title = title
        self.link = link
        self.upvotes = upvotes
        self.author = author
        self.content = content

    def fetch_content(self):
        """Fetches content from the post's link if content is empty."""
        if not self.content and self.link:
            try:
                page = requests.get(self.link, timeout=TIMEOUT)
                page.raise_for_status()
                soup = BeautifulSoup(page.text, "html.parser")
                container = (
                    soup.find("article")
                    or soup.find("main")
                    or soup.find("section")
                    or soup.body
                )
                for p in container.find_all("p", recursive=True):
                    text = p.get_text(strip=True)
                    if self._is_valid(text):
                        self.content = text
                        break
                if not self.content:
                    self.content = "(no relevant content found)"
            except requests.RequestException as e:
                self.content = f"(error fetching link: {e})"

    @staticmethod # Keep fetch_top_articles as a static method
    def fetch_top_articles(limit: int = 5) -> List[Dict]:
        """
        Fetches the top `limit` stories from Hacker News, returning a list of dicts:
        { 'id', 'title', 'url', 'score', 'content' }.
        Prefers the API's 'text' field for Ask/Show HN; otherwise scrapes minimal content.
        """
        # 1. Get the top story IDs (up to 500 IDs)
        resp = requests.get(f"{HN_API_BASE}/topstories.json", timeout=TIMEOUT)
        resp.raise_for_status()
        top_ids = resp.json()[:limit]

        articles = []
        for story_id in top_ids:
            # 2. Fetch each story’s metadata (title, url, score, text)
            item = requests.get(f"{HN_API_BASE}/item/{story_id}.json", timeout=TIMEOUT)
            item.raise_for_status()
            data = item.json()
            if not data or data.get("type") != "story":
                continue

            article = {
                "id": data["id"],
                "title": data.get("title", "").strip(),
                "url": data.get("url"),
                "score": data.get("score", 0),
                "content": "",
            }

            # 3. Use Ask/Show HN text if available (APIs return HTML in 'text')
            if data.get("text"):
                soup = BeautifulSoup(data["text"], "html.parser")
                article["content"] = soup.get_text(separator="\n", strip=True)
            else:
                # 4. Otherwise, scrape the linked page for the first valid paragraph
                if article["url"]:
                    try:
                        page = requests.get(article["url"], timeout=TIMEOUT)
                        page.raise_for_status()
                        soup = BeautifulSoup(page.text, "html.parser")
                        container = (
                            soup.find("article")
                            or soup.find("main")
                            or soup.find("section")
                            or soup.body
                        )
                        for p in container.find_all("p", recursive=True):
                            text = p.get_text(strip=True)
                            if Post._is_valid(text):
                                article["content"] = text
                                break
                        if not article["content"]:
                            article["content"] = "(no relevant content found)"
                    except requests.RequestException as e:
                        article["content"] = f"(error fetching link: {e})"\

            articles.append(article)

        return articles

    @staticmethod # Keep _is_valid as a static method
    def _is_valid(text: str) -> bool:
        """
        Filters out paragraphs that are too short, contain boilerplate or URLs.
        """
        if len(text) < 100:
            return False
        # block tokens: URLs, copyright, policy mentions
        blocked = [
            "http",
            "www.",
            "©",
            "Terms of Service",
            "Privacy Policy",
            "Advertisement",
        ]
        if any(token in text for token in blocked):
            return False
        # skip purely numeric or code-like text
        if re.match(r"^[\d\W]+$", text):
            return False
        return True