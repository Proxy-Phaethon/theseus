import dnstwist

class DNSTwistTool:
    def run(self, domain):
        return dnstwist.run(
            domain=domain,
            registered=True,
        )
