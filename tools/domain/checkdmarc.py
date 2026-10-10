import checkdmarc

class CheckDMARCTool:
    def run(self, domain):
        return checkdmarc.check_domains([domain])
