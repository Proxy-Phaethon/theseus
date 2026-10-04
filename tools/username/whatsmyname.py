import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

class WhatsMyNameTool:
    DATA_URL = (
        "https://raw.githubusercontent.com/"
        "WebBreacher/WhatsMyName/main/wmn-data.json"
    )

    DATA_PATH = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "wmn-data.json"
    )

    def __init__(self, workers=50, timeout=10):
        self.workers = workers
        self.timeout = timeout

    def run(self, username):
        sites = self._load_sites()

        results = []

        with ThreadPoolExecutor(
            max_workers=self.workers
        ) as executor:
            futures = {
                executor.submit(
                    self._check_site,
                    site,
                    username,
                ): site
                for site in sites
            }

            for future in as_completed(futures):
                result = future.result()

                if result is not None:
                    results.append(result)

        return results

    def _load_sites(self):
        self.DATA_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        if not self.DATA_PATH.exists():
            self._download_data()

        with self.DATA_PATH.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

        return [
            site
            for site in data["sites"]
            if site.get("valid", True)
        ]

    def _download_data(self):
        response = requests.get(
            self.DATA_URL,
            timeout=self.timeout,
        )

        response.raise_for_status()

        self.DATA_PATH.write_text(
            response.text,
            encoding="utf-8",
        )

    def _check_site(self, site, username):
        url = site["uri_check"].replace(
            "{account}",
            username,
        )

        headers = site.get("headers", {})

        try:
            if "post_body" in site:
                body = site["post_body"].replace(
                    "{account}",
                    username,
                )

                response = requests.post(
                    url,
                    data=body,
                    headers=headers,
                    timeout=self.timeout,
                )
            else:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                )

        except requests.RequestException:
            return None

        if not self._is_match(site, response):
            return None

        profile_url = site.get(
            "uri_pretty",
            site["uri_check"],
        ).replace(
            "{account}",
            username,
        )

        return {
            "site": site["name"],
            "category": site.get("cat"),
            "url": profile_url,
            "status_code": response.status_code,
        }

    @staticmethod
    def _is_match(site, response):
        if response.status_code != site.get("e_code"):
            return False

        e_string = site.get("e_string", "")

        if e_string and e_string not in response.text:
            return False

        m_string = site.get("m_string", "")

        if m_string and m_string in response.text:
            return False

        return True