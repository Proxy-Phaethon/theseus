from core.identifier import EntityType

from tools.ip.shodan import ShodanTool
from tools.ip.censys import CensysTool
from tools.ip.netlas import NetlasTool
from tools.ip.ipinfo import IPInfoTool
from tools.ip.ip_api import IPAPITool
from tools.ip.ipapi_is import IPAPIIsTool
from tools.ip.ripestat import RIPEstatTool
from tools.ip.team_cymru import TeamCymruTool
from tools.ip.abuseipdb import AbuseIPDBTool
from tools.ip.alienvault_otx import AlienVaultOTXTool
from tools.ip.virustotal import VirusTotalTool
from tools.ip.tor import TorExitListTool
from tools.ip.x4bnet import X4BNetTool
from tools.ip.robtex import RobtexTool
from tools.ip.tlsx import TLSXTool

from tools.domain.ldns import LDNSTool
from tools.domain.rdap import RDAPTool
from tools.domain.assetfinder import AssetfinderTool
from tools.domain.checkdmarc import CheckDMARCTool
from tools.domain.dig import DIGTool
from tools.domain.dnsx import DNSXTool
from tools.domain.subfinder import SubfinderTool
from tools.domain.virustotal import VirusTotalTool
from tools.domain.whois import WHOISTool

from tools.email.xposedornot import XposedOrNotTool
from tools.email.disify import DisifyTool

from tools.url.http import HTTPTool
from tools.url.dns import DNSTool

from tools.username.whatsmyname import WhatsMyNameTool

def build_collectors():
    return {
        EntityType.IP_ADDRESS: [
            ShodanTool(),
            CensysTool(),
            NetlasTool(),
            IPInfoTool(),
            IPAPITool(),
            IPAPIIsTool(),
            RIPEstatTool(),
            TeamCymruTool(),
            AbuseIPDBTool(),
            AlienVaultOTXTool(),
            VirusTotalTool(),
            TorExitListTool(),
            X4BNetTool(),
            RobtexTool(),
            TLSXTool(),
        ],

        EntityType.DOMAIN: [
            LDNSTool(),
            RDAPTool(),
            AssetfinderTool(),
            CheckDMARCTool(),
            DIGTool(),
            DNSXTool(),
            SubfinderTool(),
            VirusTotalTool(),
            WHOISTool(),
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