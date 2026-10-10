import contextlib
import io
import traceback
import dnstwist

class DNSTwistTool:
    def run(self, domain):
        try:
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                return dnstwist.run(
                    domain=domain,
                    registered=True,
                )
        except Exception:
            traceback.print_exc()
            raise