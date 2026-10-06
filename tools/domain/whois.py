import whois

class WHOISTool:
    def run(self, domain):
        result = whois.whois(domain)

        return {
            "domain_name": result.domain_name,
            "registrar": result.registrar,
            "creation_date": result.creation_date,
            "expiration_date": result.expiration_date,
            "updated_date": result.updated_date,
            "status": result.status,
            "name_servers": result.name_servers,
            "emails": result.emails,
            "org": result.org,
        }