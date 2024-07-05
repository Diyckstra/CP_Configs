import os
import ssl
import http.client
import json
import ipaddress
from loguru import logger
from datetime import datetime
from pprint import pprint

# ------------ V A R S ------------------------------------------------
LIMIT = 20

# Path
path = {
    "log_path": "logs",
    "input_path": "input",
    "output_path": "copied_config_from_CP_SMS"
}

# Name file of creds to CP SMS
CP_SMS_creds_file = "checkpoint_sms.json"

# ------------ F U N C T I O N S ------------------------------------------------

# Main CP API function
def CP_api_call(server, port, command, json_payload, sid):
    # https://ip_addr:port/web_api/command
    url = '/web_api/' + command
    if sid == '':
        headers = {'Content-Type' : 'application/json'}
    else:
        headers = {'Content-Type' : 'application/json', 'X-chkp-sid' : sid}

    context = ssl._create_unverified_context()
    httpClient = http.client.HTTPSConnection(server, port, timeout=60, context=context)

    try:
        httpClient.request("POST", url, json.dumps(json_payload), headers)
        response    = httpClient.getresponse()
        status      = response.status
        reason      = response.reason
        reply       = response.read()
        httpClient.close()
    except ConnectionRefusedError:
        return 504, {"message": "API server is not available"}
    except Exception as error:
        print("An exception occurred:", error)

    if status == 200:
        return status, json.loads(reply)
    else:
        return status, {"message": reason}

# Get hosts, networks, wildcards and etc from SMS
def CP_get_objects(server, port, sid, object_type, membership):
    if membership:
        body = { "limit": LIMIT, "offset": 0, "details-level": "full", "show-membership": "true" }
    else:
        body = { "limit": LIMIT, "offset": 0, "details-level": "full" }
    status, response = CP_api_call(server, port, object_type, body, sid)
    if status == 200:
        if response["total"] > 0: 
            objects = response["objects"]
            offset = LIMIT
            while response["total"] > response["to"]:
                if membership:
                    body = { "limit": LIMIT, "offset": offset, "details-level": "full", "show-membership": "true" }
                else:
                    body = { "limit": LIMIT, "offset": offset, "details-level": "full" }
                status, response = CP_api_call(server, port, object_type, body, sid)
                objects += response["objects"]
                offset += LIMIT
            return status, { "total": response["total"], "items": objects }
        else:
            return status, { "total": 0, "items": [] }
    else:
        return status, response

def CP_SMS_transform_rule(field_in_section, cashe_uid ):
    field_in_section.pop("uid")
    field_in_section.pop("domain")
    field_in_section.pop("meta-info")
    transform_objects = [
        "source",
        "destination",
        "service",
        "vpn",
        "content",
        "time",
        "action",
        "install-on",
        "track"
    ]
    for oo in transform_objects:
        if oo != "action" and oo != "track":
            oos = []
            for oo_ in field_in_section[oo]:
                try:
                    oos.append(cashe_uid[oo_])
                except:
                    print(f"No name: {oo_}")
            if oos:
                field_in_section[oo] = oos
        elif oo == "action" :
            field_in_section[oo] = cashe_uid[field_in_section[oo]]
        elif oo == "track" :
            field_in_section[oo]["type"] = cashe_uid[field_in_section[oo]["type"]]
    return field_in_section

def CP_SMS_get_rulebase_from_policy(server, port, sid, name):
    body = { "name": name, "limit": LIMIT, "offset": 0, "details-level": "full", "use-object-dictionary": "true" }
    status, response = CP_api_call(server, port, 'show-access-rulebase', body, sid)
    if status == 200 and response["total"] > 0: 
        objects = response["rulebase"]
        cashe_uid = {}
        for a in response["objects-dictionary"]:
            cashe_uid[a["uid"]] = a["name"]
        offset = LIMIT
        while response["total"] > response["to"]:
            body = { "name": name, "limit": LIMIT, "offset": offset }
            status, response = CP_api_call(server, port, 'show-access-rulebase', body, sid)
            objects += response["rulebase"]
            offset += LIMIT
            for a in response["objects-dictionary"]:
                cashe_uid[a["uid"]] = a["name"]

        rules = []
        for field_in_package in objects:
            section = "default-global-section"
            if field_in_package["type"] == "access-section":
                field_in_package.pop("uid")
                for field_in_section in field_in_package["rulebase"]:
                    field_in_section = CP_SMS_transform_rule(field_in_section, cashe_uid)
                    field_in_section["section"] = field_in_package["name"]
                    try:
                        field_in_section["name"]
                    except KeyError:
                        field_in_section["name"] = ""
                    field_in_section.pop("type")
                    rules.append(field_in_section)
            else:
                field_in_package = CP_SMS_transform_rule(field_in_package, cashe_uid)
                field_in_package["section"] = section
                try:
                    field_in_package["name"]
                except KeyError:
                    field_in_package["name"] = ""
                field_in_package.pop("type")
                rules.append(field_in_package)

        rules[-1]["name"] = "Cleanup Rule"

        return { "total": response["total"], "rulebase": rules }
    else: 
        return { "total": response["total"], "rulebase": [] }


# ------------ B E G I N ------------------------------------
# Create paths
for i in path:
    isExist = os.path.exists(path[i])
    if not isExist:
        os.makedirs(path[i])

# Logs
name_time = datetime.now().strftime("%d.%m.%Y")
# time_now = datetime.now().strftime("%H:%M %d.%m.%Y")

logger.add(f"{path['log_path']}/Log_{name_time}.log", backtrace=True, diagnose=True, rotation="250 MB")
logger.info(f"Script starts")

# Get creds to CP SMS
try:
    with open(f"{path['input_path']}/{CP_SMS_creds_file}") as file:
        R_CP_SMS = json.load(file)
    CP_SMS_fw_address = R_CP_SMS["address"]
    CP_SMS_fw_api_port = R_CP_SMS["port"]
    CP_SMS_user = R_CP_SMS["user"]
    CP_SMS_password = R_CP_SMS["password"]
    CP_SMS_domain = R_CP_SMS["domain"]

except FileNotFoundError:
    logger.error(f"Creds file {path['input_path']}/{CP_SMS_creds_file} not found.")
    quit()

# Get token
if CP_SMS_domain == '':
    CP_SMS_auth_token_body = { 
        "user": CP_SMS_user, 
        "password": CP_SMS_password, 
        "read-only": "true" 
        }
else:
    CP_SMS_auth_token_body = {
        "user": CP_SMS_user, 
        "password": CP_SMS_password, 
        "read-only": "true", 
        "domain": CP_SMS_domain}

CP_SMS_auth_token_response_status, CP_SMS_auth_token_response = CP_api_call(CP_SMS_fw_address, CP_SMS_fw_api_port, 'login', CP_SMS_auth_token_body, '')

if CP_SMS_auth_token_response_status == 200:
    CP_SMS_auth_token = CP_SMS_auth_token_response["sid"]
    logger.success(f"Authorization token received from CP SMS {CP_SMS_fw_address}")
else:
    logger.error(f"Authorization token not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_auth_token_response['message']}")
    quit()

# ------------ O B J E C T S ------------------------------------------------
# UID of objects
cashed_net_objects_UID = {}
objects = {}

# Tags objects
CP_SMS_response_get_tags_status, CP_SMS_response_get_tags = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-tags", False)
if CP_SMS_response_get_tags_status == 200:
    logger.success(f"Tags objects received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_tags["total"] > 0:
        for item in CP_SMS_response_get_tags["items"]:
            cashed_net_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    objects["tags"] = CP_SMS_response_get_tags
else:
    objects["tags"] = {}
    logger.error(f"Tags objects not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_tags}")

# Group with exclusion objects
CP_SMS_response_get_groups_with_exclusion_status, CP_SMS_response_get_groups_with_exclusion = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-groups-with-exclusion", False)
if CP_SMS_response_get_groups_with_exclusion_status == 200:
    logger.success(f"Groups-with-exclusion objects received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_groups_with_exclusion["total"] > 0:
        for item in CP_SMS_response_get_groups_with_exclusion["items"]:
            cashed_net_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    objects["groups-with-exclusion"] = CP_SMS_response_get_groups_with_exclusion
else:
    objects["groups-with-exclusion"] = {}
    logger.error(f"Groups-with-exclusion objects not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_groups_with_exclusion}")

# Host objects
CP_SMS_response_get_hosts_status, CP_SMS_response_get_hosts = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-hosts", True)
if CP_SMS_response_get_hosts_status == 200:
    logger.success(f"Hosts objects received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_hosts["total"] > 0:
        for item in CP_SMS_response_get_hosts["items"]:
            cashed_net_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    objects["hosts"] = CP_SMS_response_get_hosts
else:
    objects["hosts"] = {}
    logger.error(f"Hosts objects not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_hosts}")

# Network objects
CP_SMS_response_get_networks_status, CP_SMS_response_get_networks = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-networks", True)
if CP_SMS_response_get_networks_status == 200:
    logger.success(f"Networks objects received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_networks["total"] > 0:
        for item in CP_SMS_response_get_networks["items"]:
            cashed_net_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    objects["networks"] = CP_SMS_response_get_networks
else:
    objects["networks"] = {}
    logger.error(f"Networks objects not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_networks}")

# Wildcard objects
CP_SMS_response_get_wildcards_status, CP_SMS_response_get_wildcards = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-wildcards", False)
if CP_SMS_response_get_wildcards_status == 200:
    logger.success(f"Wildcards objects received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_wildcards["total"] > 0:
        for item in CP_SMS_response_get_wildcards["items"]:
            cashed_net_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    objects["wildcards"] = CP_SMS_response_get_wildcards
else:
    objects["wildcards"] = {}
    logger.error(f"Wildcards objects not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_wildcards}")

# Address ranges objects
CP_SMS_response_get_address_ranges_status, CP_SMS_response_get_address_ranges = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-address-ranges", False)
if CP_SMS_response_get_address_ranges_status == 200:
    logger.success(f"Address-ranges objects received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_address_ranges["total"] > 0:
        for item in CP_SMS_response_get_address_ranges["items"]:
            cashed_net_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    objects["address-ranges"] = CP_SMS_response_get_address_ranges
else:
    objects["address-ranges"] = {}
    logger.error(f"Address-ranges objects not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_address_ranges}")

# Address GSN handover groups
CP_SMS_response_get_gsn_handover_groups_status, CP_SMS_response_get_gsn_handover_groups = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-gsn-handover-groups", False)
if CP_SMS_response_get_gsn_handover_groups_status == 200:
    logger.success(f"Gsn-handover-groups objects received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_gsn_handover_groups["total"] > 0:
        for item in CP_SMS_response_get_gsn_handover_groups["items"]:
            cashed_net_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    objects["gsn-handover-groups"] = CP_SMS_response_get_gsn_handover_groups
else:
    objects["gsn-handover-groups"] = {}
    logger.error(f"Gsn-handover-groups objects not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_gsn_handover_groups}")

# Multicast address ranges objects
CP_SMS_response_get_address_ranges_status, CP_SMS_response_get_address_ranges = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-multicast-address-ranges", False)
if CP_SMS_response_get_address_ranges_status == 200:
    logger.success(f"Multicast-address-ranges objects received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_address_ranges["total"] > 0:
        for item in CP_SMS_response_get_address_ranges["items"]:
            cashed_net_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    objects["multicast-address-ranges"] = CP_SMS_response_get_address_ranges
else:
    objects["multicast-address-ranges"] = {}
    logger.error(f"Multicast-address-ranges objects not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_address_ranges}")

# Check Point Servers
CP_SMS_response_get_cp_servers_status, CP_SMS_response_get_cp_servers = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-checkpoint-hosts", False)
if CP_SMS_response_get_cp_servers_status == 200:
    logger.success(f"Check Point Servers objects received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_cp_servers["total"] > 0:
        for item in CP_SMS_response_get_cp_servers["items"]:
            cashed_net_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    objects["checkpoint-hosts"] = CP_SMS_response_get_cp_servers
else:
    objects["checkpoint-hosts"] = {}
    logger.error(f"Check Point Servers objects not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_cp_servers}")

# Check Point Simple Gateways
CP_SMS_response_get_cp_simple_gateways_status, CP_SMS_response_get_cp_simple_gateways = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-simple-gateways", False)
if CP_SMS_response_get_cp_simple_gateways_status == 200:
    logger.success(f"Check Point Simple Gateways objects received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_cp_simple_gateways["total"] > 0:
        for item in CP_SMS_response_get_cp_simple_gateways["items"]:
            cashed_net_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    objects["simple-gateways"] = CP_SMS_response_get_cp_simple_gateways
else:
    objects["simple-gateways"] = {}
    logger.error(f"Check Point Simple Gateways objects not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_cp_simple_gateways}")

# Check Point Simple Clusters
CP_SMS_response_get_cp_simple_clusters_status, CP_SMS_response_get_cp_simple_clusters = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-simple-clusters", False)
if CP_SMS_response_get_cp_simple_clusters_status == 200:
    logger.success(f"Check Point Simple Clusters objects received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_cp_simple_clusters["total"] > 0:
        for item in CP_SMS_response_get_cp_simple_clusters["items"]:
            cashed_net_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    objects["simple-clusters"] = CP_SMS_response_get_cp_simple_clusters
else:
    objects["simple-clusters"] = {}
    logger.error(f"Check Point Simple Clusters objects not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_cp_simple_clusters}")

# Check Point Simple Clusters members
CP_SMS_response_get_cp_simple_clusters_members_status, CP_SMS_response_get_cp_simple_clusters_members = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-cluster-members", False)
if CP_SMS_response_get_cp_simple_clusters_members_status == 200:
    logger.success(f"Check Point Simple Clusters members objects received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_cp_simple_clusters_members["total"] > 0:
        for item in CP_SMS_response_get_cp_simple_clusters_members["items"]:
            cashed_net_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
    objects["cluster-members"] = CP_SMS_response_get_cp_simple_clusters_members
else:
    objects["cluster-members"] = {}
    logger.error(f"Check Point Simple Clusters members objects not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_cp_simple_clusters_members}")

# Group objects
CP_SMS_response_get_groups_status, CP_SMS_response_get_groups = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-groups", True)
if CP_SMS_response_get_groups_status == 200:
    logger.success(f"Groups objects received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_groups["total"] > 0:
        for item in CP_SMS_response_get_groups["items"]:
            cashed_net_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
        for item in CP_SMS_response_get_groups["items"]:
            if item["members"]:
                tmp_members = []
                for member in item["members"]:
                    tmp_members.append(cashed_net_objects_UID[member])
                item["members"] = tmp_members
    objects["groups"] = CP_SMS_response_get_groups
else:
    objects["groups"] = {}
    logger.error(f"Groups objects not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_groups}")

# Fix groups in items
obj_types = ["hosts", "networks", "groups"]
for obj_type in obj_types:
    if objects[obj_type]["total"] > 0:
        for item in objects[obj_type]["items"]:
            if item["groups"]:
                tmp_grps = []
                for grp in item["groups"]:
                    tmp_grps.append(cashed_net_objects_UID[grp["uid"]])
                item["groups"] = tmp_grps
with open(f'{path["output_path"]}/Objects.json', 'w', encoding='utf-8') as f:
    json.dump(objects, f, ensure_ascii=False, indent=4)

# ------------ S E R V I C E S ------------------------------------------------
# UID of services
cashed_service_objects_UID = {}
services = {}

# Services TCP
CP_SMS_response_get_services_tcp_status, CP_SMS_response_get_services_tcp = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-services-tcp", True)
if CP_SMS_response_get_services_tcp_status == 200:
    logger.success(f"Services TCP received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_services_tcp["total"] > 0:
        for item in CP_SMS_response_get_services_tcp["items"]:
            cashed_service_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    services["services-tcp"] = CP_SMS_response_get_services_tcp
else:
    services["services-tcp"] = {}
    logger.error(f"Services TCP not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_services_tcp}")

# Services UDP
CP_SMS_response_get_services_udp_status, CP_SMS_response_get_services_udp = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-services-udp", True)
if CP_SMS_response_get_services_udp_status == 200:
    logger.success(f"Services UDP received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_services_udp["total"] > 0:
        for item in CP_SMS_response_get_services_udp["items"]:
            cashed_service_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    services["services-udp"] = CP_SMS_response_get_services_udp
else:
    services["services-udp"] = {}
    logger.error(f"Services UDP not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_services_udp}")

# Services ICMP
CP_SMS_response_get_services_icmp_status, CP_SMS_response_get_services_icmp = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-services-icmp", True)
if CP_SMS_response_get_services_icmp_status == 200:
    logger.success(f"Services ICMP received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_services_icmp["total"] > 0:
        for item in CP_SMS_response_get_services_icmp["items"]:
            cashed_service_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    services["services-icmp"] = CP_SMS_response_get_services_icmp
else:
    services["services-icmp"] = {}
    logger.error(f"Services ICMP not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_services_icmp}")

# Services ICMPv6
CP_SMS_response_get_services_icmpv6_status, CP_SMS_response_get_services_icmpv6 = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-services-icmp6", True)
if CP_SMS_response_get_services_icmpv6_status == 200:
    logger.success(f"Services ICMPv6 received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_services_icmpv6["total"] > 0:
        for item in CP_SMS_response_get_services_icmpv6["items"]:
            cashed_service_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    services["services-icmp6"] = CP_SMS_response_get_services_icmpv6
else:
    services["services-icmp6"] = {}
    logger.error(f"Services ICMPv6 not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_services_icmpv6}")

# Services DCE
CP_SMS_response_get_services_dce_status, CP_SMS_response_get_services_dce = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-services-dce-rpc", True)
if CP_SMS_response_get_services_dce_status == 200:
    logger.success(f"Services DCE received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_services_dce["total"] > 0:
        for item in CP_SMS_response_get_services_dce["items"]:
            cashed_service_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    services["services-dce-rpc"] = CP_SMS_response_get_services_dce
else:
    services["services-dce-rpc"] = {}
    logger.error(f"Services DCE not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_services_dce}")

# Services RPC
CP_SMS_response_get_services_RPC_status, CP_SMS_response_get_services_RPC = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-services-rpc", True)
if CP_SMS_response_get_services_RPC_status == 200:
    logger.success(f"Services RPC received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_services_RPC["total"] > 0:
        for item in CP_SMS_response_get_services_RPC["items"]:
            cashed_service_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    services["services-rpc"] = CP_SMS_response_get_services_RPC
else:
    services["services-rpc"] = {}
    logger.error(f"Services RPC not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_services_RPC}")

# Services Other
CP_SMS_response_get_services_other_status, CP_SMS_response_get_services_other = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-services-other", True)
if CP_SMS_response_get_services_other_status == 200:
    logger.success(f"Services Other received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_services_other["total"] > 0:
        for item in CP_SMS_response_get_services_other["items"]:
            cashed_service_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
    services["services-other"] = CP_SMS_response_get_services_other
else:
    services["services-other"] = {}
    logger.error(f"Services Other not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_services_other}")

# Services Groups
CP_SMS_response_get_services_groups_status, CP_SMS_response_get_services_groups = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-service-groups", True)
if CP_SMS_response_get_services_groups_status == 200:
    logger.success(f"Services Groups received from CP SMS {CP_SMS_fw_address}")
    if CP_SMS_response_get_services_groups["total"] > 0:
        for item in CP_SMS_response_get_services_groups["items"]:
            cashed_service_objects_UID[item["uid"]] = item["name"]
            item.pop("uid")
            item.pop("domain")
            item.pop("read-only")
        for item in CP_SMS_response_get_services_groups["items"]:
            if item["members"]:
                tmp_members = []
                for member in item["members"]:
                    tmp_members.append(cashed_service_objects_UID[member])
                item["members"] = tmp_members
    services["service-groups"] = CP_SMS_response_get_services_groups
else:
    services["service-groups"] = {}
    logger.error(f"Services Groups not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_services_groups}")

# Fix groups in items
service_types = ["services-tcp", "services-udp", "services-icmp", "services-icmp6", "services-dce-rpc", "services-rpc", "services-other", "service-groups"]
for service_type in service_types:
    if services[service_type]["total"] > 0:
        for item in services[service_type]["items"]:
            if item["groups"]:
                tmp_grps = []
                for grp in item["groups"]:
                    tmp_grps.append(cashed_service_objects_UID[grp["uid"]])
                item["groups"] = tmp_grps
with open(f'{path["output_path"]}/Services.json', 'w', encoding='utf-8') as f:
    json.dump(services, f, ensure_ascii=False, indent=4)

# ------------ U S E R S ------------------------------------------------

# Access Roles
CP_SMS_response_get_access_roles_status, CP_SMS_response_get_access_roles = CP_get_objects(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, "show-access-roles", False)
if CP_SMS_response_get_access_roles_status == 200:
    logger.success(f"Access roles received from CP SMS {CP_SMS_fw_address}")
    with open(f'{path["output_path"]}/Access-roles.json', 'w', encoding='utf-8') as f:
        json.dump(CP_SMS_response_get_access_roles, f, ensure_ascii=False, indent=4)
else:
    logger.error(f"Access roles not received from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_response_get_access_roles}")

# ------------ P O L I C Y ------------------------------------------------

firewall_policys = []
CP_SMS_response_access_layers_status, CP_SMS_response_access_layers = CP_api_call(CP_SMS_fw_address, CP_SMS_fw_api_port, 'show-access-layers', {"limit": LIMIT}, CP_SMS_auth_token)

if CP_SMS_response_access_layers_status == 200:
    logger.success(f"Policy access layers received from CP SMS {CP_SMS_fw_address}")
    for access_layer in CP_SMS_response_access_layers['access-layers']:
        CP_SMS_response_access_layer_status, CP_SMS_response_access_layer = CP_api_call(CP_SMS_fw_address, CP_SMS_fw_api_port, 'show-access-layer', {"name": access_layer["name"]}, CP_SMS_auth_token)
        if CP_SMS_response_access_layer["firewall"]:
            firewall_policys.append(CP_SMS_response_access_layer["name"])
else:
    logger.error(f"Policy access layers not received from CP SMS {CP_SMS_fw_address}")

for firewall_access_layer in firewall_policys:

    get_rulebase_package_responce = CP_SMS_get_rulebase_from_policy(CP_SMS_fw_address, CP_SMS_fw_api_port, CP_SMS_auth_token, firewall_access_layer)
    if get_rulebase_package_responce["total"] > 0:
        logger.success(f"Access layer with firewall blade <{firewall_access_layer}> from package <{firewall_access_layer}> received from CP SMS {CP_SMS_fw_address}")
        with open(f'{path["output_path"]}/Policy_{firewall_access_layer}.json', 'w', encoding='utf-8') as f:
            json.dump(get_rulebase_package_responce, f, ensure_ascii=False, indent=4)
    else:
        logger.warning(f"Trouble with access layer {firewall_access_layer} from package {firewall_access_layer}, total: {get_rulebase_package_responce['total']}")

# ------------ E N D ------------------------------------
# Release token
CP_SMS_release_token_response_status, CP_SMS_release_token_response = CP_api_call(CP_SMS_fw_address, CP_SMS_fw_api_port, 'logout', {}, CP_SMS_auth_token)
if CP_SMS_release_token_response_status == 200:
    logger.success(f"Authorization token released from CP SMS {CP_SMS_fw_address}")
else:
    logger.error(f"Authorization token not released from CP SMS {CP_SMS_fw_address}, message: {CP_SMS_auth_token_response['message']}")
    quit()
logger.info(f"Script completed")