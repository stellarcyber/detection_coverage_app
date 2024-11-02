import os
import sys
from enum import Enum
from pathlib import Path
import time
from typing import Any
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from loguru import logger
import requests_cache
import niquests as requests
from niquests.exceptions import (
    HTTPError as HTTPError,
    ConnectionError as ConnectionError,
    Timeout as Timeout,
    RequestException as RequestException,
)
from niquests.auth import (
    BearerTokenAuth as BearerTokenAuth,
    HTTPBasicAuth as HTTPBasicAuth,
)
import streamlit as st
from st_cookies_manager import EncryptedCookieManager
import machineid
import yaml
import urllib3
import warnings

warnings.simplefilter(action="ignore", category=FutureWarning)
urllib3.disable_warnings()

__version__ = "0.0.1"

APP_DIR: str = f"{Path.home()}/.coverage_analyzer"
LOGS_DIR = f"{APP_DIR}/logs"
Path(LOGS_DIR).mkdir(exist_ok=True, parents=True)

COOKIES: EncryptedCookieManager | None = None
thread_executor: ThreadPoolExecutor | None = None

# Enhanced logging configuration
fmt = "<yellow>{time:YYYY-MM-DD hh:mm:ssA zz}</yellow> - <green>{module}</green>:<cyan>{function}</cyan> - <level>{level}</level> - <magenta>{extra[session]}</magenta> - <level>{message}</level>"
logger.configure(
    handlers=[
        {
            "sink": sys.stdout,
            "format": fmt,
            "level": "INFO",
            "colorize": True,
            "backtrace": True,
            "diagnose": False,
        },
        {
            "sink": LOGS_DIR + "/app.log",
            "format": fmt,
            "level": "DEBUG",
            "colorize": False,
            "rotation": "10 MB",
            "retention": 10,
            "compression": "tar.gz",
            "enqueue": True,
            "backtrace": True,
            "diagnose": True,
        },
    ],
    extra={"session": None},
    patcher=lambda record: record["extra"].update(session=get_session_id()),
)


# Performance monitoring decorator
def timeit(func: Callable[..., Any]) -> Callable[..., Any]:
    def wrapped(*args, **kwargs) -> Any:
        start: float = time.time()
        result: Any = func(*args, **kwargs)
        end: float = time.time()
        elapsed = end - start
        if elapsed > 1.0:
            logger.patch(
                lambda r: r.update(function=func.__name__, module=func.__module__)
            ).debug("Executed in {:.2f}s", elapsed)
        return result

    return wrapped


def get_session_id() -> str | None:
    session_cookie: str | None = st.context.cookies.get("_streamlit_xsrf", None)
    if session_cookie is None:
        return None
    session_cookie_list: list[str] = session_cookie.split("|")
    if len(session_cookie_list) < 4:
        return None
    return session_cookie_list[2]


def get_cookie_manager() -> EncryptedCookieManager:
    return EncryptedCookieManager(
        prefix="coverage-analyzer/",
        password=os.environ.get(
            "STCA_COOKIES_PASSWORD", machineid.hashed_id("coverage-analyzer")
        ),
    )


def get_thread_pool_executor() -> ThreadPoolExecutor:
    return ThreadPoolExecutor(max_workers=1)


def read_hosts_config():
    config = {}
    config_path = Path(APP_DIR + "/hosts_config.yaml")
    if config_path.exists():
        logger.info("Reading global hosts configuration file")
        try:
            with Path(config_path).open("r") as file:
                config = yaml.safe_load(file)
            logger.debug(f"Successfully loaded {len(config)} host configurations")
        except Exception as e:
            logger.error(f"Error reading hosts config: {str(e)}")
    return config


def color_boolean(val) -> str:
    color: str = "#d63031"
    if bool(val):
        color = "#00b894"
    return "background-color: " + color


class StellarVersion(str, Enum):
    V4_3_0 = "4.3.0"
    V4_3_1 = "4.3.1"
    V4_3_7 = "4.3.7"
    V5_1_X = "5.1.x"
    V5_2_X = "5.2.x"
    V5_3_X = "5.3.x"


# Enhanced cache session with connection pooling
class CacheSession(requests_cache.session.CacheMixin, requests.Session): ...


DETECTION_VERSIONS = {
    "4.3.0": "4.3.0",
    "4.3.1": "4.3.1",
    "4.3.7": "4.3.7",
    "5.1.x": "5.1.1",
    "5.2.x": "5.2.0",
    "5.3.x": "5.3.0",
}

DATASOURCE_DISPLAY_NAME_MAP = {
    "linux_sensor": "Linux Agent",
    "windows_sensor": "Windows Agent",
    "network_sensor": "Network Sensor",
    "security_sensor": "Security Sensor",
    "fw_palo_alto": "Palo Alto Panorama(FW class)",
    "office365": "Office365",
    "gsuite": "G-Suite",
    "crowdstrike": "Crowdstrike(Endpoint)",
    "aws_cloudwatch": "AWS Cloudwatch",
    "aws_cloudtrail": "AWS Cloudtrail",
    "sentinelone_endpoint": "SentinelOne(Endpoint)",
    "barracuda_fw": "Barracuda WAF",
    "barracuda": "Barracuda WAF",
    "barracuda_waf": "Barracuda WAF",
    "barracuda_email": "Barracuda Email",
    "barracuda_security_gateway": "Barracuda Security Gateway",
    "f5_silverline": "F5 Silverline",
    "cylance": "Cylance Optics",
    "paloalto_prisma": "Palo Alto Prisma",
    "fw_fortigate": "Fortinet FortiGate(FW class)",
    "sonicfw": "SonicWall(FW class)",
    "fortinet": "Fortinet FortiGate(FW class)",
    "microsoft": "Microsoft (Not sure what this is?)",
    "fw_checkpoint": "Checkpoint(FW class)",
    "unknown": "Unknown",
    "generic_capture": "Generic Capture",
    "watchguard_fw": "WatchGuard Firewall Security Appliance",
    "microsoft_windows": " Windows Event (NXlog)",
    "wazuh_inc.": "Wazuh",
    "checkpoint_harmony_ep": "Checkpoint EDR (Harmony)",
    "linux_syslog": "Linux syslog (Amazon AMI, Ubuntu)",
    "versa_networks_fw": "Versa Networks Firewall",
    "meraki": "Meraki(FW class)",
    "nxlog": "NXlog",
    "sonicwall_vpn": "SonicWall VPN",
    "generic": "Generic",
    "ep_sophos": "Sophos Endpoint",
    "ahnlab_epp": "AhnLab Endpoint",
    "endpoint_sophos": "Sophos Endpoint",
    "dhcpd": "dhcpd (ISC DHCP)",
    "dell_idrac": "Dell iDRAC",
    "proofpoint": "Proofpoint",
    "graylog": "Graylog",
    "windows_dns_server": "Windows DNS",
    "arbor_peakflow_sp": "Arbor Peakflow",
    "hpe_switch": "HPE Switch",
    "synology_directory_server": "Synology Directory Server",
    "zscaler_zia_web": "Zscaler ZIA FW",
    "nginx": "NGINX",
    "privacy_i": "Privacy I",
    "trendmicro_proxy": "Trend Micro Proxy",
    "vmware": "VMWare",
    "android": "Android",
    "ericom_ztedge": "Ericom ZTEdge",
    "forescout": "ForeScout",
    "airgap_ransomware_kill_switch": "Airgap Ransomware Kill Switch",
    "centrify": "Centrify",
    "customized_sophosfw_microgenesis": "Sophos(FW Class)",
    "customized_sonicfw": "SonicWall(FW class)",
    "firepower": "Cisco Firepower(FW class)",
    "sunny_valley_networks_zenarmor": "Sunny Valley Networks Zenarmor",
    "cisco_umbrella": "Cisco Umbrella",
    "ips_fire_power": "Cisco Firepower(FW class)",
    "privacy": "Privacy",
    "fw_sophos": "Sophos(FW Class)",
    "mcafee_epo": "McAfee EPO",
    "secui_mf2": "SECUI MF2 Firewall",
    "sentinelone": "SentinelOne(Endpoint)",
    "ubiquiti": "Ubiquiti",
    "aix": "AIX",
    "dell_switch": "Dell Switch",
    "hp_ux": "HP UX",
    "jsonar_db_security_tool": "Jsonar Database Security Tool",
    "winsips": "WINSIPS",
    "draytek_fw": "Draytek(FW Class)",
    "lanscope_cat": "Lanscope CAT",
    "nasuni": "Nasuni",
    "penta_security_wapples": "Penta Security WAPPLES WAF",
    "symantec_messaging_gateway": "Symantec Messaging Gateway",
    "ahnlab_trusguard": "Ahnlab Trusguard",
    "aruba_switch": "Aruba Switch",
    "cef": "CEF",
    "cisco_ucs": "Cisco UCS",
    "dbsafer": "DBSafer",
    "fatpipe_sd_wan": "FatPipe Networks SD-WAN",
    "forti_analyzer": "Fortinet FortiAnalyzer",
    "hillstone": "Hillstone(FW class)",
    "juniper_switch": "Juniper Switch",
    "mcafee_ns": "McAfee NS",
    "netfilter": "Netfilter",
    "palo_alto_networks": "Palo Alto Panorama(FW class)",
    "snare_agent": "Snare Agent",
    "zscaler_zia_fw": "Zscaler ZIA FW",
    "array_sag": "Array Network Secure Access Gateway",
    "leef": "LEEF",
    "accops": "Accops",
    "ahnlab_aips": "AhnLab AIPS",
    "ahnlab_policy_center": "AhnLab Policy Center",
    "asa": "Cisco ASA",
    "avaya_switch": "Avaya Switch",
    "bluecoat_proxysg": "BlueCoatProxySG",
    "brocade_switch": "Brocade switch system and admin logs",
    "cef2": "CEF2",
    "cef_5539": "CEF 5539",
    "checkpoint": "Checkpoint(FW class)",
    "checkpoint_fw1": "Checkpoint(FW class)",
    "cisco_cucm": "Cisco CUCM",
    "cisco_esa": "Cisco ESA",
    "cisco_mds": "Cisco MDS",
    "cisco_router_switch": "Cisco routers and switches",
    "cisco_wlc": "Cisco WLC",
    "ciscoironport": "Cisco IronPort",
    "ciscovpn": "Cisco VPN",
    "extreme_airdefense": "Extreme Airdefense",
    "forti_fortigate": "Fortinet FortiGate(FW class)",
    "fortinet_fortimail": "Fortinet FortiMail",
    "juniper_srx_fw": "Juniper SSG(FW class)",
    "mailboarder_agent": "Mailboarder Agent",
    "mako_fw": "Mako Networks Firewall (Netfilter)",
    "monitor_app": "Monitorapp",
    "monitorapp_ai_waf": "Monitorapp AI WAF",
    "netapp": "NetApp",
    "netiqsso": "NetIQ SSO",
    "one_login": "OneLogin",
    "pulse_secure": "Pulse Secure",
    "redhat_openshift": "Red Hat Openshift",
    "secui_fw": "SECUI MF2 Firewall",
    "ssr_metieye": "Security Strategy Research (SSR) Metieye",
    "symantec": "Symantec Web Security",
    "vmware_nsx_t": "VMware NSX T Data Center",
    "zscaler_zpa": "Zscaler ZPA",
    "zyxel_fw": "Zyxel(FW class)",
    "aliyun": "Aliyun",
    "cisco_meraki": "Cisco Meraki",
    "corelight_sensor": "CoreLight Sensor",
    "indusface_waf": "Indusface Web Application Firewall",
    "infoblox_nios": "Infoblox NIOS",
    "juniper_ssg": "Juniper SSG(FW class)",
    "lepide": "Lepide",
    "mcafee_atd": "McAfee Advanced Threat Defense",
    "pfsense_fw": "pfSense Firewall",
    "sharetech_fw": "ShareTech Firewall",
    "sophos_alerts": "Sophos Endpoint",
    "sophos_events": "Sophos Endpoint",
    "cybereason_malops_all_types": "Cybereason (EDR)",
    "cloudtrail": "AWS Cloudtrail",
    "azure_eventhub": "Azure Eventhub",
    "mimecast_email": "Mimecast Email",
    "trendmicro_apexcentral": "Trend Micro Apex Central",
    "cybereason_sensors": "Cybereason (EDR)",
    "mikrotik": "MikroTik firewall and router",
    "okta": "Okta",
}

STELLAR_EXTRA_TACTICS = [
    "XDR SBA",
    "External Credential Access",
    "External XDR NBA",
    "External XDR UBA",
    "XDR EBA",
    "External XDR Malware",
    "XDR Intel",
    "Internal XDR NBA",
    "Internal XDR UBA",
    "Internal Credential Access",
    "Internal XDR Malware",
]

STELLAR_EXTRA_TACTICS_MAP = {
    "Credential Access": [
        "External Credential Access",
        "Internal Credential Access",
    ],
    "Execution": [
        "XDR EBA",
    ],
    "Collection": [
        "XDR SBA",
    ],
    "Discovery": [
        "XDR Intel",
    ],
    "Lateral Movement": [
        "External XDR NBA",
        "Internal XDR NBA",
    ],
    "Impact": [
        "External XDR UBA",
        "Internal XDR UBA",
    ],
}

OVERVIEW_MARKDOWN = """
    <div role="main" aria-label="Overview">
    This dashboard provides a comprehensive analysis of your **current** and **simulated** detection coverage, enabling you to make informed decisions about your security posture.

    ### Current Detection Coverage
    Current detection coverage is based on the data sources currently integrated into your system. 
    These data sources determine which Alert Types can be triggered, and these Alert Types are mapped to the XDR Kill Chain (Tactics & Techniques). 
    For example, Active Directory provides authentication logs, which are necessary for the `Internal User Login Failure Anomaly` Alert Type. 
    This Alert Type is mapped to the Credential Access (Tactic) and Brute Force (Technique). 
    Other data sources like Okta, PingIdentity, and SSH logs can also provide the necessary data for this Alert Type.
    ### Simulated Detection Coverage
    Simulated detection coverage allows you to explore the impact of integrating additional data sources that are not currently part of your Stellar Cyber setup. 
    This feature can help you simulate future purchasing decisions or evaluate the ROI of onboarding certain tools.

    The simulation uses the same analytic approach as the current detection coverage, providing a realistic projection of potential improvements.

    ### Limitations
    This analysis provides a high-level overview of the mappings between data sources and Alert Types. 
    In practice, filters applied to data sources could remove necessary data elements, affecting the accuracy of this analysis. 
    Additionally, the computed detection coverage only includes built-in Alert Types and those provided by third-party tools. 
    Custom Alert Types authored by you are not considered in this analysis, although they will be included in the "Available" and "Triggered" Alert Types.

    ### Definitions
    - **Data Source**: A distinct data source from a Connector, Log, or Stellar Cyber Sensor type.
    - **Covered**: An Alert Type, Technique, or Tactic has the necessary data to trigger if the requisite behavior occurs.
    - **Triggered**: An Alert Type, Technique, or Tactic had an actual hit during the specified time period.

    ### How to Use This Dashboard
    1. **Select a Tenant**: Choose the tenant you want to analyze.
    2. **Select a Timeframe**: Specify the time period for the analysis.
    3. **Review Current Coverage**: Examine the current detection coverage based on your existing data sources.
    4. **Simulate Additional Coverage**: Add hypothetical data sources to see how they would impact your detection coverage.
    5. **Analyze Results**: Use the insights to make informed decisions about your security infrastructure.

    By leveraging this dashboard, you can gain a deeper understanding of your detection capabilities and identify areas for improvement.

    ### Key Features
    - Real-time coverage analysis
    - Interactive visualizations
    - Data source recommendations
    - Mitre ATT&CK Navigator layer export
    </div>
"""
