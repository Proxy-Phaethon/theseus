from core.identifier import EntityType

from tools.ip.shodan import ShodanTool

from tools.domain.ldns import LDNSTool
from tools.domain.rdap import RDAPTool

from tools.email.xposedornot import XposedOrNotTool
from tools.email.disify import DisifyTool

from tools.url.http import HTTPTool
from tools.url.dns import DNSTool

from tools.username.whatsmyname import WhatsMyNameTool

def build_collectors():
    return {
    EntityType.IP_ADDRESS: [
    ShodanTool(),
    ],

    EntityType.DOMAIN: [
    LDNSTool(),
    RDAPTool(),
    ],

    EntityType.EMAIL: [
    XposedOrNotTool(),
    DisifyTool(),
    ],

    EntityType.URL: [
    HTTPTool(),
    DNSTool(),
    ],

    EntityType.USERNAME: [
    WhatsMyNameTool(),
    ],
    
    }