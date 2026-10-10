import io
from contextlib import redirect_stdout, redirect_stderr

import dnstwist

class DNSTwistTool:
    def run(self, domain):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return dnstwist.run(
                domain=domain,
                registered=True,
            )