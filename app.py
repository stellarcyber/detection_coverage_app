import streamlit as st
import os
import sys
import subprocess
import io
import pickle
import plotly.express as px
import plotly.graph_objects as go
from PyPDF2 import PdfMerger
import warnings
import pandas as pd
import numpy as np
import textwrap
import json
import requests
import requests_cache
from urllib.parse import urlencode
import datetime
import time
import urllib3
import shutil
warnings.simplefilter(action="ignore", category=FutureWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # type: ignore

requests_cache.install_cache(
    ".requests_cache",
    cache_control=True,
    expire_after=datetime.timedelta(hours=1),
    stale_if_error=True,
    
)


# self.preattackurl = "https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json"
# self.enterpriseattackurl = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

tactics = [
    "Reconnaissance",
    "Resource Development",
    "XDR SBA",
    "External Credential Access",
    "External XDR NBA",
    "External XDR UBA",
    "Initial Access",
    "XDR EBA",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evation",
    "Command and Control",
    "External XDR Malware",
    "XDR Intel",
    "Internal XDR NBA",
    "Discovery",
    "Collection",
    "Internal XDR UBA",
    "Internal Credential Access",
    "Internal XDR Malware",
    "Privilege Escalation",
    "Lateral Movement",
    "Exfiltration",
    "Impact",
]
tactic_technique_map = {
    "Reconnaissance": [
        "Active Scanning",
        "Gather Victim Host Information",
        "Gather Victim Identity Information",
        "Gather Victim Network Information",
        "Gather Victim Org Information",
        "Phishing for Information",
        "Search Closed Sources",
        "Search Open Technical Databases",
        "Search Open Websites/Domains",
        "Search Victim-Owned Websites",
    ],
    "Resource Development": [
        "Acquire Infrastructure",
        "Compromise Accounts",
        "Compromise Infrastructure",
        "Develop Capabilities",
        "Establish Accounts",
        "Obtain Capabilities",
        "Stage Capabilities",
    ],
    "XDR SBA": ["XDR Bytes Anomaly", "XDR Status Anomaly"],
    "External Credential Access": [
        "Adversary-in-the-Middle",
        "Brute Force",
        "Credentials from Password Stores",
        "Exploitation for Credential Access",
        "Forced Authentication",
        "Forge Web Credentials",
        "Input Capture",
        "Modify Authentication Process",
        "Multi-Factor Authentication Interception",
        "Multi-Factor Authentication Request Generation",
        "Network Sniffing",
        "OS Credential Dumping",
        "Steal Application Access Token",
        "Steal Web Session Cookie",
        "Steal or Forge Kerberos Tickets",
        "Unsecured Credentials",
    ],
    "External XDR NBA": [
        "XDR Command and Control Connection Exploitation",
        "XDR App Anomaly",
        "XDR Firewall Anomaly",
        "XDR Session Anomaly",
        "XDR Rule Violation",
        "XDR User Agent Anomaly",
        "XDR Clear Password",
        "XDR App Anomaly",
    ],
    "External XDR UBA": [
        "XDR Location Anomaly",
        "XDR Bytes Anomaly",
        "XDR Time Anomaly",
    ],
    "Initial Access": [
        "Drive-by Compromise",
        "Exploit Public-Facing Application",
        "External Remote Services",
        "Hardware Additions",
        "Phishing",
        "Replication Through Removable Media",
        "Supply Chain Compromise",
        "Trusted Relationship",
        "Valid Accounts",
    ],
    "XDR EBA": [
        "XDR Anomaly",
        "XDR Process Relationship Anomaly",
        "XDR Process Anomaly",
    ],
    "Execution": [
        "Command and Scripting Interpreter",
        "Container Administration Command",
        "Deploy Container",
        "Exploitation for Client Execution",
        "Inter-Process Communication",
        "Native API",
        "Scheduled Task/Job",
        "Shared Modules",
        "Software Deployment Tools",
        "System Services",
        "User Execution",
        "Windows Management Instrumentation",
    ],
    "Persistence": [
        "Account Manipulation",
        "BITS Jobs",
        "Boot or Logon Autostart Execution",
        "Boot or Logon Initialization Scripts",
        "Browser Extensions",
        "Compromise Client Software Binary",
        "Create Account",
        "Create or Modify System Process",
        "Event Triggered Execution",
        "External Remote Services",
        "Hijack Execution Flow",
        "Implant Internal Image",
        "Modify Authentication Process",
        "Office Application Startup",
        "Pre-OS Boot",
        "Scheduled Task/Job",
        "Server Software Component",
        "Traffic Signaling",
        "Valid Accounts",
    ],
    "Privilege Escalation": [
        "Abuse Elevation Control Mechanism",
        "Access Token Manipulation",
        "Boot or Logon Autostart Execution",
        "Boot or Logon Initialization Scripts",
        "Create or Modify System Process",
        "Domain Policy Modification",
        "Escape to Host",
        "Event Triggered Execution",
        "Exploitation for Privilege Escalation",
        "Hijack Execution Flow",
        "Process Injection",
        "Scheduled Task/Job",
        "Valid Accounts",
    ],
    "Defense Evation": [
        "Abuse Elevation Control Mechanism",
        "Access Token Manipulation",
        "BITS Jobs",
        "Build Image on Host",
        "Debugger Evasion",
        "Deobfuscate/Decode Files or Information",
        "Deploy Container",
        "Direct Volume Access",
        "Domain Policy Modification",
        "Execution Guardrails",
        "Exploitation for Defense Evasion",
        "File and Directory Permissions Modification",
        "Hide Artifacts",
        "Hijack Execution Flow",
        "Impair Defenses",
        "Indicator Removal on Host",
        "Indirect Command Execution",
        "Masquerading",
        "Modify Authentication Process",
        "Modify Cloud Compute Infrastructure",
        "Modify Registry",
        "Modify System Image",
        "Network Boundary Bridging",
        "Obfuscated Files or Information",
        "Plist File Modification",
        "Pre-OS Boot",
        "Process Injection",
        "Reflective Code Loading",
        "Rogue Domain Controller",
        "Rootkit",
        "Subvert Trust Controls",
        "System Binary Proxy Execution",
        "System Script Proxy Execution",
        "Template Injection",
        "Traffic Signaling",
        "Trusted Developer Utilities Proxy Execution",
        "Unused/Unsupported Cloud Regions",
        "Use Alternate Authentication Material",
        "Valid Accounts",
        "Virtualization/Sandbox Evasion",
        "Weaken Encryption",
        "XSL Script Processing",
    ],
    "Command and Control": [
        "Application Layer Protocol",
        "Communication Through Removable Media",
        "Data Encoding",
        "Data Obfuscation",
        "Dynamic Resolution",
        "Encrypted Channel",
        "Fallback Channels",
        "Ingress Tool Transfer",
        "Multi-Stage Channels",
        "Non-Application Layer Protocol",
        "Non-Standard Port",
        "Protocol Tunneling",
        "Proxy",
        "Remote Access Software",
        "Traffic Signaling",
        "Web Service",
    ],
    "External XDR Malware": ["XDR Trojan", "XDR Micellaneous Malware"],
    "XDR Intel": [
        "XDR Command and Control Reputation",
        "XDR Bad Reputation",
        "XDR Emerging Threat",
    ],
    "Internal XDR NBA": [
        "XDR Exploited Vulnerability",
        "XDR Firewall Anomaly",
        "XDR Service on Non-Standard Port",
        "XDR User Agent Anomaly",
    ],
    "Discovery": [
        "Account Discovery",
        "Application Window Discovery",
        "Browser Bookmark Discovery",
        "Cloud Infrastructure Discovery",
        "Cloud Service Dashboard",
        "Cloud Service Discovery",
        "Cloud Storage Object Discovery",
        "Container and Resource Discovery",
        "Debugger Evasion",
        "Domain Trust Discovery",
        "File and Directory Discovery",
        "Group Policy Discovery",
        "Network Service Discovery",
        "Network Share Discovery",
        "Network Sniffing",
        "Password Policy Discovery",
        "Peripheral Device Discovery",
        "Permission Groups Discovery",
        "Process Discovery",
        "Query Registry",
        "Remote System Discovery",
        "Software Discovery",
        "System Information Discovery",
        "System Location Discovery",
        "System Network Configuration Discovery",
        "System Network Connections Discovery",
        "System Owner/User Discovery",
        "System Service Discovery",
        "System Time Discovery",
        "Virtualization/Sandbox Evasion",
    ],
    "Collection": [
        "Adversary-in-the-Middle",
        "Archive Collected Data",
        "Audio Capture",
        "Automated Collection",
        "Browser Session Hijacking",
        "Clipboard Data",
        "Data Staged",
        "Data from Cloud Storage Object",
        "Data from Configuration Repository",
        "Data from Information Repositories",
        "Data from Local System",
        "Data from Network Shared Drive",
        "Data from Removable Media",
        "Email Collection",
        "Input Capture",
        "Screen Capture",
        "Video Capture",
    ],
    "Internal XDR UBA": ["XDR Asset Anomaly", "XDR Bytes Anomaly"],
    "Internal Credential Access": [
        "Adversary-in-the-Middle",
        "Brute Force",
        "Credentials from Password Stores",
        "Exploitation for Credential Access",
        "Forced Authentication",
        "Forge Web Credentials",
        "Input Capture",
        "Modify Authentication Process",
        "Multi-Factor Authentication Interception",
        "Multi-Factor Authentication Request Generation",
        "Network Sniffing",
        "OS Credential Dumping",
        "Steal Application Access Token",
        "Steal Web Session Cookie",
        "Steal or Forge Kerberos Tickets",
        "Unsecured Credentials",
    ],
    "Internal XDR Malware": ["XDR PUA", "XDR Miscellaneous Malware", "XDR Trojan"],
    # "Privilege Escalation": [
    #     "Abuse Elevation Control Mechanism",
    #     "Access Token Manipulation",
    #     "Boot or Logon Autostart Execution",
    #     "Boot or Logon Initialization Scripts",
    #     "Create or Modify System Process",
    #     "Domain Policy Modification",
    #     "Escape to Host",
    #     "Event Triggered Execution",
    #     "Exploitation for Privilege Escalation",
    #     "Hijack Execution Flow",
    #     "Process Injection",
    #     "Scheduled Task/Job",
    #     "Valid Accounts",
    # ],
    "Lateral Movement": [
        "Exploitation of Remote Services",
        "Internal Spearphishing",
        "Lateral Tool Transfer",
        "Remote Service Session Hijacking",
        "Remote Services",
        "Replication Through Removable Media",
        "Software Deployment Tools",
        "Taint Shared Content",
        "Use Alternate Authentication Material",
    ],
    "Exfiltration": [
        "Automated Exfiltration",
        "Data Transfer Size Limits",
        "Exfiltration Over Alternative Protocol",
        "Exfiltration Over C2 Channel",
        "Exfiltration Over Other Network Medium",
        "Exfiltration Over Physical Medium",
        "Exfiltration Over Web Service",
        "Scheduled Transfer",
        "Transfer Data to Cloud Account",
    ],
    "Impact": [
        "Account Access Removal",
        "Data Destruction",
        "Data Encrypted for Impact",
        "Data Manipulation",
        "Defacement",
        "Disk Wipe",
        "Endpoint Denial of Service",
        "Firmware Corruption",
        "Inhibit System Recovery",
        "Network Denial of Service",
        "Resource Hijacking",
        "Service Stop",
        "System Shutdown/Reboot",
    ],
}
techniques = {
    technique
    for techniques in tactic_technique_map.values()
    for technique in techniques
}


# This is needed because there is a mismatch of the display names in our alert <> data source mapping
# and the data source names that appear within Interflow
data_source_display_name_map = {
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

def check_for_updates():
    # Fetch updates from the remote repository
    subprocess.call(['git', 'fetch'])

    # Check if there are any updates
    result = subprocess.check_output(['git', 'status', '-uno'])

    if 'Your branch is behind' in result.decode('utf-8'):
        return True
    else:
        return False

def update_and_restart():
    # Pull updates
    subprocess.call(['git', 'pull'])
    env_py = shutil.which("streamlit")
    # print(env_py)
    # os.execv(env_py, (env_py, "run", "app.py")) # type: ignore
    st.rerun()


@st.cache_data
def getDetectionsAndDatasources(detections_version):
    """
    Retrieves detections and data sources from the detections API based on the specified version.

    Args:
        detections_version (str): The version of the detections to retrieve.

    Returns:
        Tuple[pd.DataFrame, pd.DataFrame]: A tuple containing two pandas DataFrames. The first DataFrame contains the detections
        and the second DataFrame contains the data sources.
    """

    # Make a GET request to the data sources API endpoint and retrieve the data sources
    response = requests.get("https://detections-api.herokuapp.com/get-data-sources/")
    response_df = pd.DataFrame(response.json()["data_sources"])
    data_sources_df = response_df[["_id", "name"]]

    # Make a POST request to the detections API endpoint and retrieve the detections
    response = requests.post(
        "https://detections-api.herokuapp.com/get-all-detections",
        data={"version": detections_version},
    )
    response_df = pd.DataFrame(response.json()["detections"])

    # Combine all the data sources required for each detection into a single column
    response_df["data_sources_combined"] = (
        response_df["data_sources_required"]
        + response_df["data_sources_dependency"]
        + response_df["data_sources_recommended"]
        + response_df["data_sources_default"]
        + response_df["data_sources_optional"]
    )

    # Return a tuple containing the detections DataFrame and the data sources DataFrame
    return response_df, data_sources_df


def get_datasource_id(name, data_sources_df):
    return data_sources_df[data_sources_df["name"] == name]["_id"].values[0]


def get_datasource_name(dt_id, data_sources_df):
    return data_sources_df[data_sources_df["_id"] == dt_id]["name"].values[0]


class BearerAuth(requests.auth.AuthBase):  # type: ignore
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + self.token
        return r


class StellarCyberAPI:
    headers = {"Accept": "application/json", "Content-type": "application/json"}

    def __init__(self, url, username, api_key, is_saas):
        self.api_base_url = f"https://{url}/connect/api/"
        self.username = username
        self.api_key = api_key
        self.saas = is_saas
        self.token = {"access_token": "", "exp": 0}

    def getToken(self):
        api_url = self.api_base_url + "v1/access_token"
        if int(time.time()) < self.token["exp"]:
            return self.token
        else:
            response = requests.post(
                api_url,
                auth=(self.username, self.api_key),
                headers=StellarCyberAPI.headers,
                verify=False,
            )
            self.token = response.json()
            return response.json()

    def getTenants(self):
        api_url = self.api_base_url + "v1/tenants"
        if self.saas:
            oauth = self.getToken()
            response = requests.get(
                api_url,
                auth=BearerAuth(oauth["access_token"]),
                headers=StellarCyberAPI.headers,
                verify=False,
            )
        else:
            response = requests.get(
                api_url,
                auth=(self.username, self.api_key),
                headers=StellarCyberAPI.headers,
                verify=False,
            )
        tenant_options = sorted([i["cust_name"] for i in response.json()["data"]], key=str.lower)        
        return tenant_options

    def es_search(self, index, query):
        api_url = self.api_base_url + "data/{}/_search".format(index)
        if self.saas:
            oauth = self.getToken()
            response = requests.get(
                api_url,
                data=json.dumps(query),
                auth=BearerAuth(oauth["access_token"]),
                headers=StellarCyberAPI.headers,
                verify=False,
            )
        else:
            response = requests.get(
                api_url,
                data=json.dumps(query),
                auth=(self.username, self.api_key),
                headers=StellarCyberAPI.headers,
                verify=False,
            )
        return response.json()

    def rest_search(self, route, params):
        api_url = self.api_base_url + route + "?" + urlencode(params)
        if self.saas:
            oauth = self.getToken()
            response = requests.get(
                api_url,
                auth=BearerAuth(oauth["access_token"]),
                headers=StellarCyberAPI.headers,
                verify=False,
            )
        else:
            response = requests.get(
                api_url,
                auth=(self.username, self.api_key),
                headers=StellarCyberAPI.headers,
                verify=False,
            )
        return response.json()

    def get_connector_log_data_sources(self, start_date, end_date, tenant=None):
        index = "aella-ade-*"

        tenant_filter = {
            "bool": {
                "should": [{"match_phrase": {"tenant_name": tenant}}],
                "minimum_should_match": 1,
            }
        }

        log_msgtype_filter = {
            "bool": {"should": [{"match": {"msgtype": 39}}], "minimum_should_match": 1}
        }

        connector_msgtype_filter = {
            "bool": {"should": [{"match": {"msgtype": 40}}], "minimum_should_match": 1}
        }

        date_filter = {
            "range": {
                "timestamp": {
                    "gte": start_date.strftime("%Y-%m-%d"),
                    "lte": end_date.strftime("%Y-%m-%d"),
                    "format": "strict_date_optional_time",
                }
            }
        }

        if tenant:
            log_bool_filter = {"bool": {"filter": [tenant_filter, log_msgtype_filter]}}
            connector_bool_filter = {
                "bool": {"filter": [tenant_filter, connector_msgtype_filter]}
            }
        else:
            log_bool_filter = log_msgtype_filter
            connector_bool_filter = connector_msgtype_filter

        log_query_filter = [log_bool_filter, date_filter]

        log_query = {
            "aggs": {
                "log": {
                    "terms": {
                        "field": "stage_output.msg_origin_source.keyword",
                        "order": {"_count": "desc"},
                        "size": 1000,
                    }
                }
            },
            "size": 0,
            "query": {
                "bool": {
                    "must": [],
                    "filter": log_query_filter,
                    "should": [],
                    "must_not": [],
                }
            },
        }
        response = self.es_search(index, log_query)
        logs = []
        for b in response["aggregations"]["log"]["buckets"]:
            logs.append(b["key"])

        connector_query_filter = [connector_bool_filter, date_filter]

        connector_query = {
            "aggs": {
                "connector": {
                    "terms": {
                        "field": "msg_origin.source.keyword",
                        "order": {"_count": "desc"},
                        "size": 1000,
                    }
                }
            },
            "size": 0,
            "query": {
                "bool": {
                    "must": [],
                    "filter": connector_query_filter,
                    "should": [],
                    "must_not": [],
                }
            },
        }
        response = self.es_search(index, connector_query)
        connectors = []
        for b in response["aggregations"]["connector"]["buckets"]:
            connectors.append(b["key"])

        return logs + connectors

    def get_sensor_sources(self, start_date, end_date, tenant=None):
        index = "aella-ade-*"
        sensor_types = []
        sensor_queries = [
            {
                "type": "linux_sensor",
                "sensor_type_filter": {
                    "bool": {
                        "should": [
                            {
                                "bool": {
                                    "filter": [
                                        {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"feature": "ds"}}
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                        {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"mode": "agent"}}
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                    ]
                                }
                            },
                            {
                                "bool": {
                                    "filter": [
                                        {
                                            "bool": {
                                                "should": [
                                                    {
                                                        "match_phrase": {
                                                            "feature": "modular"
                                                        }
                                                    }
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                        {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"mode": "agent"}}
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                    ]
                                }
                            },
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "msgtype_filter": {
                    "bool": {
                        "should": [
                            {
                                "bool": {
                                    "should": [{"match": {"msgtype": 37}}],
                                    "minimum_should_match": 1,
                                }
                            },
                            {
                                "bool": {
                                    "should": [{"match": {"msgtype": 34}}],
                                    "minimum_should_match": 1,
                                }
                            },
                        ],
                        "minimum_should_match": 1,
                    }
                },
            },
            {
                "type": "windows_sensor",
                "sensor_type_filter": {
                    "bool": {
                        "should": [{"match": {"feature": "wds"}}],
                        "minimum_should_match": 1,
                    }
                },
                "msgtype_filter": {
                    "bool": {
                        "should": [{"match": {"msgtype": 35}}],
                        "minimum_should_match": 1,
                    }
                },
            },
            {
                "type": "network_sensor",
                "sensor_type_filter": {
                    "bool": {
                        "should": [
                            {
                                "bool": {
                                    "filter": [
                                        {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"feature": "ds"}}
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                        {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"mode": "device"}}
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                    ]
                                }
                            },
                            {
                                "bool": {
                                    "filter": [
                                        {
                                            "bool": {
                                                "should": [
                                                    {
                                                        "match_phrase": {
                                                            "feature": "modular"
                                                        }
                                                    }
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                        {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"mode": "device"}}
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                    ]
                                }
                            },
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "msgtype_filter": {
                    "bool": {
                        "should": [{"match": {"msgtype": 37}}],
                        "minimum_should_match": 1,
                    }
                },
            },
            {
                "type": "security_sensor",
                "sensor_type_filter": {
                    "bool": {
                        "should": [{"match": {"feature": "sds"}}],
                        "minimum_should_match": 1,
                    }
                },
                "msgtype_filter": {
                    "bool": {
                        "should": [
                            {
                                "bool": {
                                    "should": [{"match": {"msgtype": 37}}],
                                    "minimum_should_match": 1,
                                }
                            },
                            {
                                "bool": {
                                    "should": [{"match": {"msgtype": 33}}],
                                    "minimum_should_match": 1,
                                }
                            },
                        ],
                        "minimum_should_match": 1,
                    }
                },
            },
        ]

        for sensor_query in sensor_queries:
            tenant_filter = {
                "bool": {
                    "should": [{"match_phrase": {"tenant_name": tenant}}],
                    "minimum_should_match": 1,
                }
            }

            sensor_type_filter = sensor_query["sensor_type_filter"]
            msgtype_filter = sensor_query["msgtype_filter"]

            date_filter = {
                "range": {
                    "timestamp": {
                        "gte": start_date.strftime("%Y-%m-%d"),
                        "lte": end_date.strftime("%Y-%m-%d"),
                        "format": "strict_date_optional_time",
                    }
                }
            }

            if tenant:
                bool_filter = {
                    "bool": {
                        "filter": [tenant_filter, sensor_type_filter, msgtype_filter]
                    }
                }
            else:
                bool_filter = {"bool": {"filter": [sensor_type_filter, msgtype_filter]}}

            query_filter = [bool_filter, date_filter]

            timeseries_query = {
                "aggs": {
                    "date": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "1d",
                            "time_zone": "+00:00",
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": start_date.strftime("%Y-%m-%d"),
                                "max": end_date.strftime("%Y-%m-%d"),
                            },
                        },
                        "aggs": {
                            "out_bytes_delta_total": {
                                "sum": {"field": "out_bytes_delta"}
                            }
                        },
                    }
                },
                "size": 0,
                "query": {
                    "bool": {
                        "must": [],
                        "filter": query_filter,
                        "should": [],
                        "must_not": [],
                    }
                },
            }

            response = self.es_search(index, timeseries_query)
            sensor_stats = {
                "volume_per_day": {"date": [], "volume": []},
                "cumulative_volume": 0,
                "unique_sensors": 0,
            }
            for b in response["aggregations"]["date"]["buckets"]:
                sensor_stats["volume_per_day"]["date"].append(b["key_as_string"][0:10])
                sensor_stats["volume_per_day"]["volume"].append(
                    b["out_bytes_delta_total"]["value"]
                )
                sensor_stats["cumulative_volume"] = sum(
                    sensor_stats["volume_per_day"]["volume"]
                )
            if sensor_stats["cumulative_volume"] > 0:
                sensor_types.append(sensor_query["type"])

        return sensor_types

    def alert_stats(self, start_date, end_date, tenant=None):
        """
        Stats: unique triggered alert types
        """

        alert_stats = {"unique_alert_types": {}}

        index = "aella-ser-*"

        # Unique alert type count
        tenant_filter = {
            "bool": {
                "should": [{"match_phrase": {"tenant_name": tenant}}],
                "minimum_should_match": 1,
            }
        }

        date_filter = {
            "range": {
                "timestamp": {
                    "gte": start_date.strftime("%Y-%m-%d"),
                    "lte": end_date.strftime("%Y-%m-%d"),
                    "format": "strict_date_optional_time",
                }
            }
        }

        if tenant:
            query_filter = [tenant_filter, date_filter]
        else:
            query_filter = date_filter

        base_count_query = {
            "aggs": {
                "alert_type": {
                    "terms": {
                        "field": "xdr_event.display_name.keyword",
                        "order": {"_count": "desc"},
                        "size": 10000,
                    }
                }
            },
            "size": 0,
            "query": {
                "bool": {
                    "must": [],
                    "filter": query_filter,
                    "should": [],
                    "must_not": [],
                }
            },
        }

        count_response = self.es_search(index, base_count_query)
        alert_type_hits = {}
        for a in count_response["aggregations"]["alert_type"]["buckets"]:
            alert_type_hits[a["key"]] = a["doc_count"]
        alert_stats["alert_type_hits"] = alert_type_hits

        return alert_stats


VARS = [
    "host",
    "user",
    "api_key",
    "is_saas",
    "detections_version",
    "tenant"
    # "timeframe"
]


def getRealDatasources(data_sources_df, api, tenant_name, timeframe, data_source_display_name_map):
    """
    Returns a tuple containing information about the real data sources available for a given tenant and timeframe.

    Parameters:
    -----------
    data_sources_df : pandas.DataFrame
        A DataFrame containing information about the data sources available for the tenant.
    api : stellarapi.StellarAPI
        An instance of the StellarAPI class used to retrieve data from the Stellar platform.
    tenant_name : str
        The name of the tenant for which to retrieve data.
    timeframe : tuple
        A tuple containing two datetime objects representing the start and end of the timeframe for which to retrieve data.
    data_source_display_name_map : dict
        A dictionary mapping data source IDs to their display names.

    Returns:
    --------
    tuple
        A tuple containing the following elements:
        - alert_type_hits: a dictionary containing information about the alert types and their counts.
        - real_data_sources: a list of data source IDs that are available in the data_sources_df DataFrame.
        - data_sources_np: a list of data source IDs that are not available in the data_sources_df DataFrame.
        - additional_data_source_options: a list of data source IDs that are available in the data_sources_df DataFrame but have not been selected yet.
    """
    # Get the connector log data sources and sensor data sources for the given timeframe and tenant
    connector_log_data_sources = api.get_connector_log_data_sources(
        timeframe[0], timeframe[1], tenant_name
    )
    sensor_data_sources = api.get_sensor_sources(
        timeframe[0], timeframe[1], tenant_name
    )
    
    # Get the alert type hits for the given timeframe and tenant
    alert_type_hits = api.alert_stats(timeframe[0], timeframe[1], tenant_name)[
        "alert_type_hits"
    ]
    
    # Combine the connector log data sources and sensor data sources
    data_sources_raw = connector_log_data_sources + sensor_data_sources
    
    # Initialize lists to store the real data sources, non-present data sources, and additional data source options
    real_data_sources = []
    data_sources_np = []
    
    # Iterate through the combined data sources
    for ds in data_sources_raw:
        # Check if the data source is in the data source display name map and not present in the data_sources_df DataFrame
        if (
            ds in data_source_display_name_map
            and ds not in data_sources_df["_id"].values
        ):
            # Get the data source from the data_sources_df DataFrame using its display name
            tmp_ds = data_sources_df[
                data_sources_df["name"] == data_source_display_name_map[ds]
            ]
            # If the data source is present in the DataFrame, add its ID to the real_data_sources list
            if tmp_ds.shape[0] > 0:
                real_data_sources.append(tmp_ds["_id"].values[0])
        # If the data source is present in the data_sources_df DataFrame, add its ID to the real_data_sources list
        elif ds in data_sources_df["_id"].values:
            real_data_sources.append(ds)
        # If the data source is not present in either the data source display name map or the data_sources_df DataFrame, add its ID to the data_sources_np list
        else:
            data_sources_np.append(ds)

    # Get the additional data source options by selecting the data sources that are present in the data_sources_df DataFrame but not in the real_data_sources list
    additional_data_source_options = sorted(list(data_sources_df[
        ~data_sources_df["_id"].isin(real_data_sources)
    ]["_id"].values), key=str.lower)
    
    # Return a tuple containing the alert type hits, real data sources, non-present data sources, and additional data source options
    return (
        alert_type_hits,
        real_data_sources,
        data_sources_np,
        additional_data_source_options,
    )


@st.cache_data
def get_matching_alert_types_count_from_ds(tactic, technique, response_df, data_sources):
    """
    Returns the count of matching alert types from the given response dataframe and data sources.

    Parameters:
    tactic (str): The XDR tactic to match.
    technique (str): The XDR technique to match.
    response_df (pandas.DataFrame): The response dataframe to search for matching alert types.
    data_sources (list): The list of data sources to match.

    Returns:
    int: The count of matching alert types.
    """
    # Create a boolean mask for rows where the tactic matches
    tactic_mask = response_df["XDR Tactic"] == tactic

    # Create a boolean mask for rows where the technique matches (if technique is not None)
    technique_mask = response_df["XDR Technique"] == technique if technique else True

    # Create a boolean mask for rows where any of the data sources match
    data_sources_mask = response_df["data_sources_combined"].apply(lambda x: any(item in x for item in data_sources))

    # Return the count of rows where all masks are True
    return response_df[tactic_mask & technique_mask & data_sources_mask].shape[0]


@st.cache_data
def get_matching_alert_types_count_from_hits(tactic, technique, response_df, alert_type_hits):
    """
    Returns the count of matching alert types from the given response dataframe and alert type hits.

    Args:
        tactic (str): The XDR tactic to match.
        technique (str): The XDR technique to match.
        response_df (pandas.DataFrame): The response dataframe to search for matching alert types.
        alert_type_hits (dict): A dictionary of alert types and their hit counts.

    Returns:
        int: The count of matching alert types.
    """
    # Create a query to filter the dataframe
    # The query checks if the 'XDR Tactic' column matches the given tactic
    # and if the 'XDR Display Name' column is in the list of hit alert types
    query = (response_df["XDR Tactic"] == tactic) & (response_df["XDR Display Name"].isin(alert_type_hits))

    # If a technique is given, add it to the query
    # The query now also checks if the 'XDR Technique' column matches the given technique
    if technique:
        query &= (response_df["XDR Technique"] == technique)

    # Apply the query to the dataframe and return the number of rows in the resulting dataframe
    return response_df[query].shape[0]


@st.cache_data
def getTacticStats(tactics, response_df, data_sources, alert_type_hits):
    """
    Returns a dictionary containing statistics for each tactic in the given list of tactics.

    Parameters:
    tactics (list): A list of tactics to get statistics for.
    response_df (pandas.DataFrame): A DataFrame containing response data.
    data_sources (dict): A dictionary containing data sources.
    alert_type_hits (dict): A dictionary containing alert type hits.

    Returns:
    dict: A dictionary containing statistics for each tactic in the given list of tactics.
    """
    tactic_stats = {}
    for tactic in tactics:
        if tactic not in tactic_stats:
            tactic_stats[tactic] = {}

        # All alerts built in or third party
        tactic_stats[tactic]["total_alert_types_available"] = response_df[
            response_df["XDR Tactic"] == tactic
        ].shape[0]

        # All alerts covered based on data sources
        tactic_stats[tactic][
            "total_alert_types_covered"
        ] = get_matching_alert_types_count_from_ds(
            tactic, None, response_df, data_sources
        )

        # All alerts based on triggerd
        tactic_stats[tactic][
            "total_alert_types_triggered"
        ] = get_matching_alert_types_count_from_hits(
            tactic, None, response_df, alert_type_hits
        )
    return tactic_stats


@st.cache_data
def getTechniqueStats(
    tactics, tactic_technique_map, response_df, data_sources, alert_type_hits
):
    technique_stats = {}
    for tactic in tactics:
        if tactic not in technique_stats:
            technique_stats[tactic] = {}

        for technique in tactic_technique_map[tactic]:
            if technique not in technique_stats[tactic]:
                technique_stats[tactic][technique] = {}

            # All alerts built in or third party
            technique_stats[tactic][technique][
                "total_alert_types_available"
            ] = response_df[
                (response_df["XDR Tactic"] == tactic)
                & (response_df["XDR Technique"] == technique)
            ].shape[
                0
            ]

            # All alerts covered based on data sources
            technique_stats[tactic][technique][
                "total_alert_types_covered"
            ] = get_matching_alert_types_count_from_ds(
                tactic, technique, response_df, data_sources
            )

            # All alerts based on triggerd
            technique_stats[tactic][technique][
                "total_alert_types_triggered"
            ] = get_matching_alert_types_count_from_hits(
                tactic, technique, response_df, alert_type_hits
            )
    return technique_stats


@st.cache_data
def getAlertTypeStats(response_df, alert_type_hits, data_sources):
    alert_type_stats = {
        "total_alert_types_available": response_df.shape[0],
        "total_alert_types_triggered": len(alert_type_hits),
        "alert_type_details": [],
    }

    # data_sources_with_alert_types = []
    # df[[iscomedy(l) for l in df.genre.values.tolist()]]
    # for ds in data_sources:
    #     if ds in alert_types.columns:
    #         data_sources_with_alert_types.append(ds)

    # alert_types['data_sources_combined'] = alert_types[data_sources_with_alert_types].apply(lambda row: '_'.join(row.values.astype(str)), axis=1)
    count = 0
    for index, row in response_df.iterrows():
        detail = {
            "alert_type": row["XDR Display Name"],
            "tactic": row["XDR Tactic"],
            "technique": row["XDR Technique"],
        }
        # if set(row['data_sources_combined']).issubset(set(data_sources)):
        if any(item in row["data_sources_combined"] for item in data_sources):
            count += 1
            detail["covered"] = True
        else:
            detail["covered"] = False
        detail["triggered"] = False
        if row["XDR Display Name"] in alert_type_hits:
            if alert_type_hits[row["XDR Display Name"]] > 0:
                detail["triggered"] = True

        alert_type_stats["alert_type_details"].append(detail)

    alert_type_stats["total_alert_types_covered"] = count
    return alert_type_stats


@st.cache_data
def getDataSourceStats(response_df, data_sources):
    data_source_stats = []
    # alert_types_with_data_sources = response_df[response_df["data_sources_combined"].map(lambda x: set(x).issubset(set(data_sources)))]

    for ds in data_sources:
        ds_alert_types = response_df[
            response_df["data_sources_combined"].map(
                lambda x: set([ds]).issubset(set(x))
            )
        ]
        data_source_stats.append(
            {
                "data_source": ds,
                "alert_types_covered": ds_alert_types.shape[0],
                "techniques_covered": ds_alert_types["XDR Technique"].unique().shape[0],
                "tactics_covered": ds_alert_types["XDR Tactic"].unique().shape[0],
            }
        )
    data_source_stats_df = pd.DataFrame(data_source_stats)
    return data_source_stats_df


@st.cache_data
def getTacticsCovered(tactic_stats):
    tactics_covered = 0
    tactics_triggered = 0
    for key, val in tactic_stats.items():
        if val["total_alert_types_covered"] > 0:
            tactics_covered += 1
        if val["total_alert_types_triggered"] > 0:
            tactics_triggered += 1
    tactics_available = len(tactic_stats)
    tactic_covered_per = tactics_covered / tactics_available
    return (tactic_covered_per, tactics_available, tactics_covered, tactics_triggered)


@st.cache_data
def getTechniquesCovered(technique_stats):
    uniq_techniques = {}
    for key, val in technique_stats.items():
        for tech_key, tech_val in val.items():
            if tech_key in uniq_techniques:
                if (
                    uniq_techniques[tech_key] == 0
                    and tech_val["total_alert_types_covered"] > 0
                ):
                    uniq_techniques[tech_key] = tech_val["total_alert_types_covered"]
            else:
                uniq_techniques[tech_key] = tech_val["total_alert_types_covered"]

    techniques_covered = 0
    for key, val in uniq_techniques.items():
        if val > 0:
            techniques_covered += 1

    uniq_techniques = {}
    for key, val in technique_stats.items():
        for tech_key, tech_val in val.items():
            if tech_key in uniq_techniques:
                if (
                    uniq_techniques[tech_key] == 0
                    and tech_val["total_alert_types_triggered"] > 0
                ):
                    uniq_techniques[tech_key] = tech_val["total_alert_types_triggered"]
            else:
                uniq_techniques[tech_key] = tech_val["total_alert_types_triggered"]

    techniques_triggered = 0
    for key, val in uniq_techniques.items():
        if val > 0:
            techniques_triggered += 1

    techniques_available = len(techniques)
    technique_per = techniques_covered / techniques_available
    return (
        technique_per,
        techniques_available,
        techniques_covered,
        techniques_triggered,
    )


@st.cache_data
def getAlertTypesCovered(alert_type_stats):
    alert_type_per = (
        alert_type_stats["total_alert_types_covered"]
        / alert_type_stats["total_alert_types_available"]
    )
    return alert_type_per


@st.cache_data
def getTacticTable(tactic_stats, detections_df, data_sources):
    tactic_table = []
    for tactic, data in tactic_stats.items():
        table_elem = {
            "tactic": tactic,
            # 'num_available': data['total_alert_types_available'],
            # 'num_covered': data['total_alert_types_covered'],
            # 'num_triggered': data['total_alert_types_triggered']
        }
        if data["total_alert_types_available"] > 0:
            table_elem["available"] = True
        else:
            table_elem["available"] = False
        if data["total_alert_types_covered"] > 0:
            table_elem["covered"] = True
            table_elem["recommended"] = None
        else:
            table_elem["covered"] = False
            # [item for row in matrix for item in row]
            all_ds = list(
                set(
                    [
                        d
                        for ds in detections_df[detections_df["XDR Tactic"] == tactic][
                            "data_sources_required"
                        ].values
                        for d in ds
                        if d not in data_sources
                    ]
                    + [
                        d
                        for ds in detections_df[detections_df["XDR Tactic"] == tactic][
                            "data_sources_dependency"
                        ].values
                        for d in ds
                        if d not in data_sources
                    ]
                    + [
                        d
                        for ds in detections_df[detections_df["XDR Tactic"] == tactic][
                            "data_sources_recommended"
                        ].values
                        for d in ds
                        if d not in data_sources
                    ]
                    + [
                        d
                        for ds in detections_df[detections_df["XDR Tactic"] == tactic][
                            "data_sources_default"
                        ].values
                        for d in ds
                        if d not in data_sources
                    ]
                    + [
                        d
                        for ds in detections_df[detections_df["XDR Tactic"] == tactic][
                            "data_sources_optional"
                        ].values
                        for d in ds
                        if d not in data_sources
                    ]
                )
            )
            if len(all_ds) > 0:
                table_elem["recommended"] = ", ".join(all_ds)
            else:
                table_elem["recommended"] = None
        if data["total_alert_types_triggered"] > 0:
            table_elem["triggered"] = True
        else:
            table_elem["triggered"] = False
        tactic_table.append(table_elem)
    tactic_table_df = pd.DataFrame(tactic_table)
    return tactic_table_df


@st.cache_data
def getTechniqueTable(technique_stats, detections_df, data_sources):
    technique_table = []
    for tactic, data in technique_stats.items():
        for technique, tech_data in data.items():
            table_elem = {
                "tactic": tactic,
                "technique": technique,
                # 'num_available': tech_data['total_alert_types_available'],
                # 'num_covered': tech_data['total_alert_types_covered'],
                # 'num_triggered': tech_data['total_alert_types_triggered']
            }
            if tech_data["total_alert_types_available"] > 0:
                table_elem["available"] = True
            else:
                table_elem["available"] = False
            if tech_data["total_alert_types_covered"] > 0:
                table_elem["covered"] = True
                table_elem["recommended"] = None
            else:
                table_elem["covered"] = False
                all_ds = list(
                    set(
                        [
                            d
                            for ds in detections_df[
                                (detections_df["XDR Technique"] == technique)
                                & (detections_df["XDR Tactic"] == tactic)
                            ]["data_sources_required"].values
                            for d in ds
                            if d not in data_sources
                        ]
                        + [
                            d
                            for ds in detections_df[
                                (detections_df["XDR Technique"] == technique)
                                & (detections_df["XDR Tactic"] == tactic)
                            ]["data_sources_dependency"].values
                            for d in ds
                            if d not in data_sources
                        ]
                        + [
                            d
                            for ds in detections_df[
                                (detections_df["XDR Technique"] == technique)
                                & (detections_df["XDR Tactic"] == tactic)
                            ]["data_sources_recommended"].values
                            for d in ds
                            if d not in data_sources
                        ]
                        + [
                            d
                            for ds in detections_df[
                                (detections_df["XDR Technique"] == technique)
                                & (detections_df["XDR Tactic"] == tactic)
                            ]["data_sources_default"].values
                            for d in ds
                            if d not in data_sources
                        ]
                        + [
                            d
                            for ds in detections_df[
                                (detections_df["XDR Technique"] == technique)
                                & (detections_df["XDR Tactic"] == tactic)
                            ]["data_sources_optional"].values
                            for d in ds
                            if d not in data_sources
                        ]
                    )
                )
                # all_ds = set([d for ds in detections_df[(detections_df["XDR Technique"] == technique) & (detections_df["XDR Tactic"] == tactic)]["data_sources_combined"].values for d in ds if d not in data_sources])
                if len(all_ds) > 0:
                    table_elem["recommended"] = ", ".join(all_ds)
                else:
                    table_elem["recommended"] = None
            if tech_data["total_alert_types_triggered"] > 0:
                table_elem["triggered"] = True
            else:
                table_elem["triggered"] = False
            technique_table.append(table_elem)
    technique_table_df = pd.DataFrame(technique_table)
    return technique_table_df


def color_boolean(val):
    color = ""
    if val == True:
        color = "#00b894"
    elif val == False:
        color = "#d63031"
    return "background-color: %s" % color


def getStage(technique, detections_df):
    stage = None
    if stage in detections_df[detections_df["XDR Technique"] == technique]:
        stage = detections_df[detections_df["XDR Technique"] == technique]["XDR Kill Chain Stage"].values[0]
    return stage


# @st.cache_data
def getTreemapPlot(map_display, detections_df, technique_stats):
    if map_display == "Covered":
        map_config = {
            "num": "total_alert_types_covered",
            "denom": "total_alert_types_available",
        }
    else:
        map_config = {
            "num": "total_alert_types_triggered",
            "denom": "total_alert_types_covered",
        }

    tmp = []
    for tactic, techniques in technique_stats.items():
        for technique, details in techniques.items():
            if details["total_alert_types_available"] > 0:
                cov_per = (
                    details["total_alert_types_covered"]
                    / details["total_alert_types_available"]
                )
            else:
                cov_per = 0.0
            if details["total_alert_types_covered"] > 0:
                trig_per = (
                    details["total_alert_types_triggered"]
                    / details["total_alert_types_covered"]
                )
            else:
                trig_per = 0.0
            tmp.append(
                {
                    "Tactic": tactic,
                    "Technique": technique,
                    "Alert Types Available": details["total_alert_types_available"],
                    "Alert Types Covered": details["total_alert_types_covered"],
                    "Alert Types Triggered": details["total_alert_types_triggered"],
                    "Covered Percentage": cov_per,
                    "Triggered Percentage": trig_per,
                    "Label": f"{textwrap.fill(technique, width=12, break_long_words=True)}\n({details['total_alert_types_covered']} / {details['total_alert_types_available']})",
                }
            )

    df = pd.DataFrame(tmp)

    # st.dataframe(df)
    # df["all"] = "Detections"

    fig = px.treemap(
        df[df["Alert Types Available"] > 0],
        path=[px.Constant("Detections"), "Tactic", "Technique"],
        color="Covered Percentage",
        labels="Label",
        color_continuous_scale="RdBu",
        #  color_continuous_midpoint=0.5
        hover_data=[
            "Alert Types Available",
            "Alert Types Covered",
            "Alert Types Triggered",
        ],
    )
    fig.update_layout(margin=dict(t=50, l=25, r=25, b=25))

    return fig


@st.cache_data
def getHeatmapPlot(map_display, tactic_stats, technique_stats):
    if map_display == "Covered":
        map_config = {
            "num": "total_alert_types_covered",
            "denom": "total_alert_types_available",
        }
    else:
        map_config = {
            "num": "total_alert_types_triggered",
            "denom": "total_alert_types_covered",
        }

    line_break_width = 24
    labels = [[]]
    colors = [[]]
    hovers = [[]]
    for tactic in tactics:
        # label = '<br>'.join(textwrap.wrap(tactic, width=line_break_width, break_long_words=False, break_on_hyphens=True)) + '<br>(' + str(tactic_stats[tactic][map_config['num']]) + ' / ' + str(tactic_stats[tactic][map_config['denom']]) + ')'
        label = f"{'<br>'.join(textwrap.wrap(tactic, width=line_break_width, break_on_hyphens=True, break_long_words=False))}:<br>({str(tactic_stats[tactic][map_config['num']])}/{str(tactic_stats[tactic][map_config['denom']])})<br>"
        # label = f"{textwrap.fill(tactic, width=line_break_width, break_long_words=False, replace_whitespace=True)}<br>({tactic_stats[tactic][map_config['num']]} / {tactic_stats[tactic][map_config['denom']]})"
        labels[0].append(label)

        if (
            tactic_stats[tactic][map_config["denom"]] == 0
            or tactic_stats[tactic][map_config["num"]] == 0
        ):
            if tactic_stats[tactic]["total_alert_types_available"] == 0:
                colors[0].append(0.0)
            else:
                colors[0].append(0.1)
        else:
            colors[0].append(
                tactic_stats[tactic][map_config["num"]]
                / tactic_stats[tactic][map_config["denom"]]
            )

        hover = f"<b>Tactic: </b>{tactic}<br>Total Alert Types Available: {tactic_stats[tactic][map_config['denom']]}<br>Total Alert Types Covered: {tactic_stats[tactic]['total_alert_types_covered']}<br>Total Alert Types Triggered: {tactic_stats[tactic]['total_alert_types_triggered']}"
        hovers[0].append(hover)
    col = 0
    for key, val in tactic_technique_map.items():
        row = 1
        for tech in val:
            if len(labels) < row + 1:
                labels.append([None] * len(tactics))
                colors.append([None] * len(tactics))
                hovers.append([None] * len(tactics))
            labels[row][col] = (
                "<br>".join(
                    textwrap.wrap(
                        tech,
                        width=line_break_width,
                        break_long_words=False,
                        break_on_hyphens=True,
                    )
                )
                + "<br>("
                + str(technique_stats[key][tech][map_config["num"]])
                + " / "
                + str(technique_stats[key][tech][map_config["denom"]])
                + ")"
            )
            if (
                technique_stats[key][tech][map_config["denom"]] == 0
                or technique_stats[key][tech][map_config["num"]] == 0
            ):
                if technique_stats[key][tech]["total_alert_types_available"] == 0:
                    colors[row][col] = 0.0
                else:
                    colors[row][col] = 0.1
            else:
                colors[row][col] = (
                    technique_stats[key][tech][map_config["num"]]
                    / technique_stats[key][tech][map_config["denom"]]
                )
            hovers[row][col] = (
                "<b>Technique: </b>"
                + tech
                + "<br>Total Alert Types Available: "
                + str(technique_stats[key][tech][map_config["denom"]])
                + "<br>Total Alert Types Covered: "
                + str(technique_stats[key][tech]["total_alert_types_covered"])
                + "<br>Total Alert Types Triggered: "
                + str(technique_stats[key][tech]["total_alert_types_triggered"])
            )
            row += 1
        col += 1

    # Change None in labels to ''
    for row in range(len(labels)):
        for col in range(len(labels[row])):
            if labels[row][col] is None:
                labels[row][col] = ""

    # Change None in colors to .0
    for row in range(len(colors)):
        for col in range(len(colors[row])):
            if colors[row][col] is None:
                colors[row][col] = 0.0

    colorscale = [
        [0.0, "#f2f1f3"],
        # [.0, '#0f1740'],
        [0.1, "#F8C3CF"],
        [0.3, "#FFE4E1"],
        [0.5, "#FFF9D8"],
        [0.7, "#CEF7B5"],
        [0.9, "#A3EB98"],
        [1.0, "#A3EB98"],
    ]

    fig = px.imshow(
        colors,
        # text_auto=False,
        # binary_format="png",
        # binary_backend="pil",
        # binary_compression_level=4,
        # binary_string=False,
        origin="upper",
        color_continuous_scale=colorscale,
        aspect="auto",
        title="XDR Kill Chain Coverage",
        # contrast_rescaling=None,
        contrast_rescaling="infer",
        width=1800,
        height=2400
        # width=1632,
        # height=2112
    )
    fig.update_traces(
        text=labels,
        texttemplate="%{text}",
        customdata=hovers,
        hovertemplate="%{customdata}",
        xgap=0.8,
        ygap=0.8
    )
    fig.update_layout(
        autosize=True,
        uniformtext_minsize=12,
        plot_bgcolor="#ffffff"
        # uniformtext_mode="show",
        # plot_bgcolor="#f2f1f3"
    )
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    fig.update_coloraxes(showscale=False)

    return fig


@st.cache_data
def getAlertRecommendations(x, data_sources, detections_df):
    # Initialize an empty list to store the recommendations
    recs = []
    # Loop over the columns of interest
    for col in ["data_sources_required", "data_sources_dependency", "data_sources_recommended", "data_sources_default", "data_sources_optional"]:
        # Extract the relevant data from the detections dataframe
        # for the given XDR display name (x) and column (col)
        # using a nested list comprehension
        recs += [d for ds in detections_df[detections_df["XDR Display Name"] == x][col].values for d in ds if d not in data_sources]
    # Combine the recommendations into a single string, removing duplicates
    # if the list is not empty, otherwise return None
    return ", ".join(set(recs)) if recs else None


def checkConfigState():
    if (
        "host" in st.session_state
        and "user" in st.session_state
        and "api_key" in st.session_state
        and "is_saas" in st.session_state
        and "detections_version" in st.session_state
    ):
        if (
            st.session_state.host == ""
            or st.session_state.user == ""
            or st.session_state.api_key == ""
        ):
            return False
        else:
            return True
    else:
        return False


def initState():
    if os.path.exists(".saved"):
        st.session_state.configured = True
        with open(".saved", "rb") as f:
            conf_dict = pickle.load(f)
            for var in VARS:
                if var in conf_dict and var not in st.session_state:
                    st.session_state[var] = conf_dict[var]

    if "configured" not in st.session_state:
        st.session_state.configured = False
    if "host" not in st.session_state:
        st.session_state.host = ""
    if "user" not in st.session_state:
        st.session_state.user = ""
    if "api_key" not in st.session_state:
        st.session_state.api_key = ""
    if "is_saas" not in st.session_state:
        st.session_state.is_saas = True
    if "detections_version" not in st.session_state:
        st.session_state.detections_version = "4.3.7"
    if "tenant" not in st.session_state:
        st.session_state.tenant = None
    # if "timeframe" not in st.session_state:
    #     st.session_state.timeframe = [datetime.datetime.today() - datetime.timedelta(days=7), datetime.datetime.today()]


def saveState(host, user, api_key, is_saas, detections_version, tenant):
    conf_dict = {
        "host": host,
        "user": user,
        "api_key": api_key,
        "is_saas": is_saas,
        "detections_version": detections_version,
        "tenant": tenant
        # "timeframe": timeframe,
    }
    with open(".saved", "wb") as f:
        pickle.dump(conf_dict, f)

    st.session_state.configured = True


@st.cache_data
def getFullReport(
    tenant,
    tactic_table_df,
    technique_table_df,
    tactics_available,
    tactics_covered,
    tactics_triggered,
    techniques_available,
    techniques_covered,
    techniques_triggered,
    alert_type_stats,
    tactic_covered_per,
    technique_per,
    alert_type_per,
    alert_type_stats_df,
    coverage_plot,
):
    table_color_map = {True: "#00b894", False: "#d63031"}

    fig1 = go.Figure(
        data=[
            go.Table(
                header=dict(
                    values=["<b>Tactic</b>", "<b>Available</b>", "<b>Covered</b>", "<b>Triggered</b>", "<b>Recommended</b>"],
                    line_color="#2d3436",
                    fill_color="#17233E",
                    align="center",
                    font=dict(color="#ffffff", size=8),
                ),
                cells=dict(
                    values=[tactic_table_df[col] for col in tactic_table_df.columns],
                    line_color="#2d3436",
                    fill_color=[
                        "#dfe6e9",
                        [table_color_map[v] for v in tactic_table_df.available.values],
                        [table_color_map[v] for v in tactic_table_df.covered.values],
                        [table_color_map[v] for v in tactic_table_df.triggered.values],
                        "#dfe6e9",
                    ],
                    align="left",
                    font=dict(
                        color=[
                            "#2d3436",
                            [table_color_map[v] for v in tactic_table_df.available.values],
                            [table_color_map[v] for v in tactic_table_df.covered.values],
                            [table_color_map[v] for v in tactic_table_df.triggered.values],
                            ["#dfe6e9" if v is None else "#2d3436" for v in tactic_table_df.recommended.values],
                        ],
                        size=8,
                    ),
                ),
                columnwidth=[75, 30, 30, 30, 175],
            )
        ]
    )

    fig1.update_layout(
        margin=dict(l=20, r=20, t=500, b=20),
        autosize=False,
        width=816,
        height=1056,
        paper_bgcolor="#f2f1f3",
    )

    fig1.add_annotation(
        dict(
            font=dict(color="#2d3436", size=24),
            x=0.5,
            y=1.65,
            showarrow=False,
            text=f"{tenant} Detection Coverage Report",
            textangle=0,
            xanchor="center",
            xref="paper",
            yref="paper",
        )
    )

    annotations = [
        {
            "text": f"<b>{title}</b><br><b>{percentage:.0%}</b><br>Number of {title} in XDR Kill Chain: <b>{total_available}</b><br>Number of {title} covered with data sources: <b>{total_covered}</b><br>Number of {title} triggered in time period: <b>{total_triggered}</b>",
            "x": x,
            "y": 1.25,
            "showarrow": False,
            "textangle": 0,
            "xanchor": xanchor,
            "xref": "paper",
            "yref": "paper",
            "font": {"color": "#2d3436", "size": 9},
        }
        for title, percentage, total_available, total_covered, total_triggered, xanchor, x in [
            ("Tactics Covered", tactic_covered_per, tactics_available, tactics_covered, tactics_triggered, "left", 0.00),
            ("Techniques Covered", technique_per, techniques_available, techniques_covered, techniques_triggered, "center", 0.5),
            ("Alert Types Covered", alert_type_per, alert_type_stats["total_alert_types_available"], alert_type_stats["total_alert_types_covered"], alert_type_stats["total_alert_types_triggered"], "right", 1.0),
        ]
    ]

    for annotation in annotations:
        fig1.add_annotation(annotation)
    # tech_df1, tech_df2, tech_df3 = np.array_split(technique_table_df, 3)
    table_color_map = {True: "#00b894", False: "#d63031"}
    tech_pdfs = []
    for i, tech_df in enumerate(np.array_split(technique_table_df, 7)):
        tmp_fig = go.Figure(
            data=[
                go.Table(
                    header=dict(
                        values=[
                            "<b>Tactic</b>",
                            "<b>Technique</b>",
                            "<b>Available</b>",
                            "<b>Covered</b>",
                            "<b>Triggered</b>",
                            "<b>Recommended</b>",
                        ],
                        line_color="#2d3436",
                        fill_color="#17233E",
                        align="center",
                        font=dict(color="#ffffff", size=8),
                    ),
                    cells=dict(
                        values=[tech_df.tactic, tech_df.technique, tech_df.available, tech_df.covered, tech_df.triggered, tech_df.recommended],  # type: ignore
                        # fill_color='white',
                        # line_color=['black', 'black', ['green' if v else 'red' for v in tech_df.available.values], ['green' if v else 'red' for v in tech_df.covered.values], ['green' if v else 'red' for v in tech_df.triggered.values]],
                        line_color="#2d3436",
                        fill_color=["#dfe6e9", "#dfe6e9", ["#00b894" if v else "#d63031" for v in tech_df.available.values], ["#00b894" if v else "#d63031" for v in tech_df.covered.values], ["#00b894" if v else "#d63031" for v in tech_df.triggered.values], "#dfe6e9"],  # type: ignore
                        align="left",
                        font=dict(
                            color=["#2d3436", "#2d3436", ["#00b894" if v else "#d63031" for v in tech_df.available.values], ["#00b894" if v else "#d63031" for v in tech_df.covered.values], ["#00b894" if v else "#d63031" for v in tech_df.triggered.values], ["#dfe6e9" if v is None else "#2d3436" for v in tech_df.recommended.values]],  # type: ignore
                            size=8,
                        ),
                    ),
                    columnwidth=[75, 100, 30, 30, 30, 150],
                )
            ]
        )
        # width=816, height=1056
        tmp_fig.update_layout(
            margin=dict(l=20, r=20, t=60, b=20),
            autosize=False,
            width=816,
            height=1056,
            title=f"Techniques Coverage Table Part {i+1}",
            paper_bgcolor="#f2f1f3",
        )
        # tmp_fig.update_layout(margin=dict(l=20, r=20, t=75, b=20), autosize=False, width=1632, height=2112, title=f"Techniques Coverage Table Part {i}")
        # fig2.update_layout(margin=dict(l=20, r=20, t=20, b=20), autosize=True, width=2448, height=3168)
        tmp_pdf = io.BytesIO()
        tmp_fig.write_image(tmp_pdf, format="pdf", scale=1.0)
        tech_pdfs.append(tmp_pdf)

    alert_pdfs = []
    for i, alert_df in enumerate(np.array_split(alert_type_stats_df, 6)):
        tmp_fig = go.Figure(
            data=[
                go.Table(
                    header=dict(
                        values=[
                            "<b>Technique</b>",
                            "<b>Alert Type</b>",
                            "<b>Covered</b>",
                            "<b>Triggered</b>",
                            "<b>Recommended</b>",
                        ],
                        line_color="#2d3436",
                        fill_color="#17233E",
                        align="center",
                        font=dict(color="#ffffff", size=8),
                    ),
                    cells=dict(
                        values=[alert_df.technique, alert_df.alert_type, alert_df.covered, alert_df.triggered, alert_df.recommended],  # type: ignore
                        # fill_color='white',
                        # line_color=['black', 'black', ['green' if v else 'red' for v in tech_df.available.values], ['green' if v else 'red' for v in tech_df.covered.values], ['green' if v else 'red' for v in tech_df.triggered.values]],
                        line_color="#2d3436",
                        fill_color=["#dfe6e9", "#dfe6e9", ["#00b894" if v else "#d63031" for v in alert_df.covered.values], ["#00b894" if v else "#d63031" for v in alert_df.triggered.values], "#dfe6e9"],  # type: ignore
                        align="left",
                        font=dict(
                            color=["#2d3436", "#2d3436", ["#00b894" if v else "#d63031" for v in alert_df.covered.values], ["#00b894" if v else "#d63031" for v in alert_df.triggered.values], ["#dfe6e9" if (v is None or pd.isna(v)) else "#2d3436" for v in alert_df.recommended.values]],  # type: ignore
                            size=8,
                        ),
                    ),
                    columnwidth=[100, 100, 30, 30, 150],
                )
            ]
        )
        # width=816, height=1056
        tmp_fig.update_layout(
            margin=dict(l=20, r=20, t=60, b=20),
            autosize=False,
            width=816,
            height=1056,
            title=f"Alert Type Coverage Table Part {i+1}",
            paper_bgcolor="#f2f1f3",
        )
        # tmp_fig.update_layout(margin=dict(l=20, r=20, t=75, b=20), autosize=False, width=1632, height=2112, title=f"Techniques Coverage Table Part {i}")
        # fig2.update_layout(margin=dict(l=20, r=20, t=20, b=20), autosize=True, width=2448, height=3168)
        tmp_pdf = io.BytesIO()
        tmp_fig.write_image(tmp_pdf, format="pdf", scale=1.0)
        alert_pdfs.append(tmp_pdf)

    pdf1 = io.BytesIO()
    chart_pdf = io.BytesIO()
    fig1.write_image(pdf1, format="pdf", scale=1.0)
    coverage_plot.write_image(chart_pdf, format="pdf", scale=1.0)
    file = io.BytesIO()
    pdfs = [pdf1] + tech_pdfs + alert_pdfs + [chart_pdf]

    merger = PdfMerger()

    for pdf in pdfs:
        merger.append(pdf)

    merger.write(file)
    merger.close()
    file.seek(0)
    return file


def main():
    st.set_page_config(
        page_title="Detection Coverage Dashboard",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={
            "About": "This is a Streamlit application using the Stellar Cyber API to generate a Detection Coverage Dashboard. Authored by Will Fales wfales@stellarcyber.ai"
        },
    )
    st.title("Detection Coverage Dashboard")
    st.caption("Version: 0.1.2")
    if st.button('Check for Updates'):
        with st.status("Checking for updates...", expanded=True) as updates_status:
            st.write("Checking remote repository...")
            if check_for_updates():
                st.write("Found updates!")
                updates_status.update(label="Found updates!", state="complete", expanded=True)
                st.button('Update', type="primary", on_click=update_and_restart)  # type: ignore  # noqa: F821
            else:
                st.write("No updates found.")
                updates_status.update(label="No updates found.", state="complete", expanded=False)

    st.subheader("Overview", divider=True)
    st.markdown(
        """
                This dashboard allows users to understand their **current** and **simulated** detection coverage.

                Current detection coverage is determined by the current data sources in the system, which determine which Alert Types have the data needed to run, which are then mapped to the XDR Kill Chain (Tactics & Techniques). For example, Active Directory provides authentication logs, which provides the needed data for Alert Type `Internal User Login Failure Anomaly`, which is mapped to Credential Access (Tactic) and Brute Force (Technique). Active Directory is just one applicable data source for this Alert Type however, Okta, PingIdentity, ssh logs - all also work.

                Simulated detection coverage takes the same analytic approach, but allows users simulate "adding" other data sources that are currently not integrated into Stellar Cyber. This could simulate future purchasing decisions or helping with ROI analysis on onboarding certain existing tools.

                #### Limitations
                This is a high level analysis of the mappings between data sources to Alert Types. In practice, a user could apply a filter to a data source and remove needed data elements for certain Alert Types, which would break this analysis.

                The detection coverage that is computed is ONLY for the built-in Alert Types, or the Alert Types provided via 3rd Party Tools. It does not consider the Custom Alert Types you have authored. However, any Custom Alert Types will be considered for "Available" and "Triggered" Alert Types.

                #### Definitions
                * Data Source - a distinct data source from a Connector, Log, or Stellar Cyber Sensor type
                * Covered - An Alert Type, Technique, or Tactic has the data needed to trigger if the requisite behavior occurs
                * Triggered - An Alert Type, Technique, or Tactic had an actual hit during the specified time period
                """
    )

    initState()

    if checkConfigState():
        config_section = st.sidebar.expander("Configuration", expanded=False)
    else:
        config_section = st.sidebar.expander("Configuration", expanded=True)

    stellar_cyber_host = config_section.text_input(
        "Stellar Cyber Host",
        key="host",
        help="Your Stellar Cyber Host, Ex. example.stellarcyber.cloud",
        autocomplete="on",
        placeholder="example.stellarcyber.ai",
        disabled=False,
        label_visibility="visible",
    )

    stellar_cyber_user = config_section.text_input(
        "Stellar Cyber User",
        key="user",
        help="The Stellar Cyber API User Email",
        autocomplete="on",
        placeholder="example.user@stellarcyber.ai",
        disabled=False,
        label_visibility="visible",
    )

    stellar_api_key = config_section.text_input(
        "Stellar Cyber API Key",
        key="api_key",
        type="password",
        help="The Stellar Cyber API Key for the User",
        autocomplete="password",
        placeholder="API Key",
        disabled=False,
        label_visibility="visible",
    )

    stellar_is_saas = config_section.checkbox(
        "Is SaaS (or >= 4.3.6)",
        key="is_saas",
        help="Is the DP SaaS or On-Prem version >= 4.3.6?",
    )

    stellar_detections_version = config_section.selectbox(
        "Stellar Cyber Detections Version",
        key="detections_version",
        options=["4.3.7", "4.3.6", "4.3.5", "4.3.4"],
    )

    if config_section.button("Save"):
        saveState(
            st.session_state.host,
            st.session_state.user,
            st.session_state.api_key,
            st.session_state.is_saas,
            st.session_state.detections_version,
            st.session_state.tenant,
            # st.session_state.timeframe,
        )
        st.rerun()

    if st.session_state.configured:
        options_section = st.sidebar.expander("Options", expanded=True)

        api = StellarCyberAPI(
            url=st.session_state.host,
            username=st.session_state.user,
            api_key=st.session_state.api_key,
            is_saas=st.session_state.is_saas,
        )
        tenant_options = api.getTenants()
        if (
            st.session_state.tenant is not None
            and len(tenant_options) > 0
            and st.session_state.tenant not in tenant_options
        ):
            st.session_state.tenant = None
        tenant = options_section.selectbox(
            "Select Tenant",
            help="Select the tenant to run the dashboard for.",
            key="tenant",
            index=None,
            options=tenant_options,
        )

        timeframe = options_section.date_input(
            "Time Range",
            value=[
                datetime.datetime.today() - datetime.timedelta(days=7),
                datetime.datetime.today(),
            ],
            help="Select the time range to run the dashboard for.",
            key="timeframe",
        )

        if st.session_state.tenant is None or st.session_state.timeframe is None:
            st.warning("Please Select a Tenant and Time Range")
            st.stop()
        else:
            saveState(
                st.session_state.host,
                st.session_state.user,
                st.session_state.api_key,
                st.session_state.is_saas,
                st.session_state.detections_version,
                st.session_state.tenant,
                # st.session_state.timeframe,
            )
    else:
        st.warning("Please Enter Stellar Cyber Credentials")
        st.stop()

    detections_df, data_sources_df = getDetectionsAndDatasources(
        st.session_state.detections_version
    )

    alert_type_hits, real_data_sources, data_sources_np, additional_data_source_options = getRealDatasources(data_sources_df, api, st.session_state.tenant, st.session_state.timeframe, data_source_display_name_map)  # type: ignore

    simulation_section = st.sidebar.expander("Simulate", expanded=True)

    additional_data_sources = simulation_section.multiselect(
        "Additional Data Sources",
        help="Select Additional Data Sources to Simulate Coverage.",
        key="additional_data_sources",
        # on_change=reRun,
        options=additional_data_source_options,
    )

    download_full_report = st.sidebar.empty()

    if len(data_sources_np) > 0:
        st.sidebar.info(
            f'INFO: Data Sources that matched no mappings and were not considered in results - {", ".join(i for i in data_sources_np)}'
        )

    data_sources = real_data_sources + st.session_state.additional_data_sources
    tactic_stats = getTacticStats(tactics, detections_df, data_sources, alert_type_hits)
    technique_stats = getTechniqueStats(
        tactics, tactic_technique_map, detections_df, data_sources, alert_type_hits
    )
    alert_type_stats = getAlertTypeStats(detections_df, alert_type_hits, data_sources)
    data_source_stats_df = getDataSourceStats(detections_df, data_sources)
    (
        tactic_covered_per,
        tactics_available,
        tactics_covered,
        tactics_triggered,
    ) = getTacticsCovered(tactic_stats)
    (
        technique_per,
        techniques_available,
        techniques_covered,
        techniques_triggered,
    ) = getTechniquesCovered(technique_stats)
    alert_type_per = getAlertTypesCovered(alert_type_stats)

    st.subheader("Metrics", divider=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="Tactics Covered", value=f"{tactic_covered_per:.0%}")
        st.divider()
        st.markdown("#### Tactics")
        st.markdown(f"Number of Tactics in XDR Kill Chain: **{tactics_available}**")
        st.markdown(
            f"Number of Tactics covered with data sources: **{tactics_covered}**"
        )
        st.markdown(
            f"Number of Tactics triggered in time period: **{tactics_triggered}**"
        )
    with col2:
        st.metric(label="Techniques Covered", value=f"{technique_per:.0%}")
        st.divider()
        st.markdown("#### Techniques")
        st.markdown(
            f"Number of Techniques in XDR Kill Chain: **{techniques_available}**"
        )
        st.markdown(
            f"Number of Techniques covered with data sources: **{techniques_covered}**"
        )
        st.markdown(
            f"Number of Techniques triggered in time period: **{techniques_triggered}**"
        )
    with col3:
        st.metric(label="Alert Types Covered", value=f"{alert_type_per:.0%}")
        st.divider()
        st.markdown("#### Alert Types")
        st.markdown(
            f"Number of Alert Types in XDR Kill Chain: **{alert_type_stats['total_alert_types_available']}**"
        )
        st.markdown(
            f"Number of Alert Types covered with data sources: **{alert_type_stats['total_alert_types_covered']}**"
        )
        st.markdown(
            f"Number of Alert Types triggered in time period: **{alert_type_stats['total_alert_types_triggered']}**"
        )

    # st.divider()
    st.subheader("Tactics Coverage Table", divider=True)

    tactic_table_df = getTacticTable(tactic_stats, detections_df, data_sources)
    # st.dataframe(tactic_table_df.style.applymap(color_boolean, subset=['available', 'covered', 'triggered']),
    st.dataframe(
        tactic_table_df.style.applymap(
            color_boolean, subset=["available", "covered", "triggered"]
        ),
        use_container_width=True,
        hide_index=True,
        column_order=["tactic", "available", "covered", "triggered", "recommended"],
        column_config={
            "tactic": st.column_config.TextColumn(label="Tactic", width="small"),
            "available": st.column_config.CheckboxColumn(
                label="Available", width="small"
            ),
            "covered": st.column_config.CheckboxColumn(label="Covered", width="small"),
            "triggered": st.column_config.CheckboxColumn(
                label="Triggered", width="small"
            ),
            "recommended": st.column_config.ListColumn(
                label="Recommended Datasources", width="large"
            ),
        },
    )

    col1, col2, col3, col4 = st.columns(4)
    with col4:
        st.download_button(
            "Download Tactic Table as CSV",
            tactic_table_df.to_csv(index=False).encode("utf-8"),
            "tactics_coverage.csv",
            "text/csv",
            key="download-tactics-csv",
        )

    st.subheader("Techniques Coverage Table", divider=True)

    technique_table_df = getTechniqueTable(technique_stats, detections_df, data_sources)
    # st.dataframe(technique_table_df.style.applymap(color_boolean, subset=['available', 'covered', 'triggered']), use_container_width=True, hide_index=True)
    st.dataframe(
        technique_table_df.style.applymap(
            color_boolean, subset=["available", "covered", "triggered"]
        ),
        use_container_width=True,
        hide_index=True,
        column_order=[
            "tactic",
            "technique",
            "available",
            "covered",
            "triggered",
            "recommended",
        ],
        column_config={
            "tactic": st.column_config.TextColumn(label="Tactic", width="small"),
            "technique": st.column_config.TextColumn(label="Technique", width="medium"),
            "available": st.column_config.CheckboxColumn(
                label="Available", width="small"
            ),
            "covered": st.column_config.CheckboxColumn(label="Covered", width="small"),
            "triggered": st.column_config.CheckboxColumn(
                label="Triggered", width="small"
            ),
            "recommended": st.column_config.ListColumn(
                label="Recommended Datasources", width="large"
            ),
        },
    )

    col1, col2, col3, col4 = st.columns(4)
    with col4:
        st.download_button(
            "Download Technique Table as CSV",
            technique_table_df.to_csv(index=False).encode("utf-8"),
            "techniques_coverage.csv",
            "text/csv",
            key="download-techniques-csv",
        )

    st.subheader("Alert Types Coverage Table", divider=True)

    alert_type_stats_df = pd.DataFrame(alert_type_stats["alert_type_details"])
    alert_type_stats_df["recommended"] = alert_type_stats_df[
        alert_type_stats_df["covered"] == False
    ]["alert_type"].map(
        lambda x: getAlertRecommendations(x, data_sources, detections_df)
    )
    # all_ds = set([d for ds in detections_df[detections_df["XDR Technique"] == technique]["data_sources_combined"].values for d in ds if d not in data_sources])
    st.dataframe(
        alert_type_stats_df.style.applymap(
            color_boolean, subset=["covered", "triggered"]
        ),
        use_container_width=True,
        hide_index=True,
        column_order=["technique", "alert_type", "covered", "triggered", "recommended"],
        column_config={
            "technique": st.column_config.TextColumn(label="Technique", width="medium"),
            "alert_type": st.column_config.TextColumn(
                label="Alert Type", width="medium"
            ),
            "covered": st.column_config.CheckboxColumn(label="Covered", width="small"),
            "triggered": st.column_config.CheckboxColumn(
                label="Triggered", width="small"
            ),
            "recommended": st.column_config.ListColumn(
                label="Recommended Datasources", width="large"
            ),
        },
    )

    col1, col2, col3, col4 = st.columns(4)
    with col4:
        st.download_button(
            "Download Alert Type Table as CSV",
            alert_type_stats_df.to_csv(index=False).encode("utf-8"),
            "alert_types_coverage.csv",
            "text/csv",
            key="download-alert-types-csv",
        )

    st.subheader("Data Sources Coverage Table", divider=True)

    st.dataframe(
        data_source_stats_df,
        use_container_width=True,
        hide_index=True,
        column_order=[
            "data_source",
            "alert_types_covered",
            "techniques_covered",
            "tactics_covered",
        ],
        column_config={
            "data_source": st.column_config.TextColumn(label="Data Source"),
            "alert_types_covered": st.column_config.NumberColumn(
                label="Alert Types Covered"
            ),
            "techniques_covered": st.column_config.NumberColumn(
                label="Techniques Covered"
            ),
            "tactics_covered": st.column_config.NumberColumn(label="Tactics Covered"),
        },
    )

    col1, col2, col3, col4 = st.columns(4)
    with col4:
        st.download_button(
            "Download Data Sources Table as CSV",
            data_source_stats_df.to_csv(index=False).encode("utf-8"),
            "data_sources_coverage.csv",
            "text/csv",
            key="download-data-sources-csv",
        )

    st.subheader("Killchain Coverage Map", divider=True)

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.selectbox(
            "Plot Chart by Covered or Triggered",
            options=["Covered", "Triggered"],
            index=0,
            key="plot_by",
            help="Select whether you would like the Heatmap to calculate on Covered alert types or Triggered Alert types. (Triggered may give better visibility into custom alerts)",
        )
    
    # coverage_plot = getHeatmapPlot(
    #     st.session_state.plot_by, tactic_stats, technique_stats
    # )
    
    # col1, col2, col3, col4 = st.columns(4)
    # with col1:
    #     st.download_button(
    #         "Download Coverage Heatmap as PDF",
    #         coverage_plot.to_image(format="pdf"),
    #         f"{st.session_state.tenant}_coverage_heatmap.pdf",
    #         "application/pdf",
    #         key="download-coverage-heatmap-pdf",
    #     )
    #     st.download_button(
    #         "Download Coverage Heatmap as PNG",
    #         coverage_plot.to_image(format="png", scale=4.0),
    #         f"{st.session_state.tenant}_coverage_heatmap.png",
    #         "image/png",
    #         key="download-coverage-heatmap-png",
    #     )

    # st.plotly_chart(coverage_plot, use_container_width=True, theme="streamlit")

    with col2:
        st.selectbox(
            "Type of Chart",
            options=["Heatmap", "Treemap"],
            index=0,
            key="chart_type",
            help="What type of chart you would like to generate",
        )

    if st.session_state.chart_type == "Heatmap":
        coverage_plot = getHeatmapPlot(
            st.session_state.plot_by, tactic_stats, technique_stats
        )
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.download_button(
                "Download Coverage Heatmap as PDF",
                coverage_plot.to_image(format="pdf"),
                f"{st.session_state.tenant}_coverage_heatmap.pdf",
                "application/pdf",
                key="download-coverage-heatmap-pdf",
            )
            st.download_button(
                "Download Coverage Heatmap as PNG",
                coverage_plot.to_image(format="png", scale=4.0),
                f"{st.session_state.tenant}_coverage_heatmap.png",
                "image/png",
                key="download-coverage-heatmap-png",
            )

        st.plotly_chart(coverage_plot, use_container_width=True, theme="streamlit")

    elif st.session_state.chart_type == "Treemap":
        coverage_plot = getTreemapPlot(
            st.session_state.plot_by, detections_df, technique_stats
        )
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.download_button(
                "Download Coverage Treemap as PDF",
                coverage_plot.to_image(format="pdf"),
                f"{st.session_state.tenant}_coverage_treemap.pdf",
                "application/pdf",
                key="download-coverage-treemap-pdf",
            )
        st.plotly_chart(coverage_plot, use_container_width=True, theme="streamlit") # type: ignore

    st.divider()

    download_full_report.download_button(
        "Download Full PDF Report",
        getFullReport(
            st.session_state.tenant,
            tactic_table_df,
            technique_table_df,
            tactics_available,
            tactics_covered,
            tactics_triggered,
            techniques_available,
            techniques_covered,
            techniques_triggered,
            alert_type_stats,
            tactic_covered_per,
            technique_per,
            alert_type_per,
            alert_type_stats_df,
            coverage_plot, # type: ignore
        ), 
        f"{st.session_state.tenant}_detection_coverage_report.pdf",
        "application/pdf",
        key="download-detection-coverage-report-pdf",
    )

    st.dataframe(
        detections_df,
        height=800,
        use_container_width=True,
        hide_index=True,
        column_order=[
            "XDR Kill Chain Stage",
            "XDR Tactic",
            "XDR Technique",
            "XDR Event Name",
            #    "Relevant Minimum Data Fields for code and display",
            #    "Required Data Fields for Enrichment",
            "data_sources_combined",
        ],
        column_config={
            "XDR Kill Chain Stage": "Kill Chain Stage",
            "XDR Tactic": "Tactic",
            "XDR Technique": "Technique",
            "XDR Event Name": "Alert Type",
            #  "Relevant Minimum Data Fields for code and display": st.column_config.ListColumn(label="Minimum Data Fields", width=None),
            #  "Required Data Fields for Enrichment": st.column_config.ListColumn(label="Min. for Enrichment", width=None),
            "data_sources_combined": st.column_config.ListColumn(
                label="Recommended Data Sources", width=None
            ),
        },
    )

    col1, col2, col3, col4 = st.columns(4)
    with col4:
        st.download_button(
            "Download All Detections Mappings as CSV",
            alert_type_stats_df.to_csv(index=False).encode("utf-8"),
            "all_detections_mappings.csv",
            "text/csv",
            key="download-all-detections-csv",
        )


if __name__ == "__main__":
    main()
