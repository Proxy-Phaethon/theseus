import asyncio

from maigret import maigret

class MaigretTool:
    def run(self, username):
        return asyncio.run(
            maigret(
                username,
                site_list=None,
                timeout=10,
                max_connections=50,
                print_banner=False,
                debug=False,
                no_progressbar=True,
            )
        )