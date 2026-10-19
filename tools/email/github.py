import requests

class GitHubTool:
    BASE_URL = "https://api.github.com/search/commits"

    def run(self, email):
        response = requests.get(
            self.BASE_URL,
            params={
                "q": f"author-email:{email.strip()}",
            },
            headers={
                "Accept": "application/vnd.github+json",
            },
            timeout=10,
        )

        response.raise_for_status()

        return response.json()