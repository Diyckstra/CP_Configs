from pprint import pprint
import json
import os
import sys
from loguru import logger
from datetime import datetime
from ipaddress import ip_network

# ------------ V A R S ------------------------------------------------

# Path
path = {
    "log_path": "logs",
    "input_path": "input",
    "output_path": "parsed_configs"
}

# ------------ F U N C T I O N S ------------------------------------------------
def CP_NGFW_parse_config(path, config_name, config):
    parsed_config = {
        "snmp": [],
        "arp": [],
        "interface": [],
        "static_route": [],
        "pbr": [],
        "other": []
        }

    for line_config in config:
        if line_config:
            
            # Comment && empty lines
            if line_config[0] == '#' or line_config[0] == ' ':
                None

            # SNMP
            elif line_config.find("set snmp ") != -1:
                parsed_config["snmp"].append(line_config)

            # ARP
            elif line_config.find("add arp proxy ") != -1:
                parsed_config["arp"].append(line_config)

            # PBR
            elif line_config.find("set pbr ") != -1:
                parsed_config["pbr"].append(line_config)

            # Static Route
            elif line_config.find("set static-route ") != -1:
                parsed_config["static_route"].append(line_config)

            # Interface
            elif ((line_config.find("add interface ") != -1) or 
                (line_config.find("set interface ") != -1) or 
                (line_config.find("set pim interface ") != -1) or 
                (line_config.find("set bonding group ") != -1) or
                (line_config.find("add bonding group ") != -1) or
                (line_config.find("set igmp interface ") != -1)):
                parsed_config["interface"].append(line_config)

            # Other
            else:
                parsed_config["other"].append(line_config)

    return parsed_config

# ------------ B E G I N ------------------------------------
# Logs
name_time = datetime.now().strftime("%d.%m.%Y")
# time_now = datetime.now().strftime("%H:%M %d.%m.%Y")

logger.add(f"{path['log_path']}/CP_NGFW_Log_{name_time}.log", backtrace=True, diagnose=True, rotation="250 MB")
logger.info(f"Script starts")

configs = []

for root, dirs, files in os.walk(path["input_path"]):
    for filename in files:
        if filename[-4:] == (".cfg"):
            configs.append(filename)

if configs:
    logger.success(f"The following configs were found: {configs}")
else:
    logger.error("Configs not found")
    quit()

for ngfw_config in configs:

    # Input
    config_path = f"{path['input_path']}/{ngfw_config}"
    input_config = open(config_path, mode='r', encoding="UTF-8")
    config = input_config.read().splitlines()
    input_config.close()
    parsed_config = CP_NGFW_parse_config(path["input_path"], ngfw_config, config)

    # Output
    subdir_path = f"{path['output_path']}/parsed_{ngfw_config}"
    subdir_path_exist = os.path.exists(subdir_path)
    if not subdir_path_exist:
        os.makedirs(subdir_path)

    # Output of unparsed config
    for item in parsed_config:
        if parsed_config[item]:
            with open(f'{path["output_path"]}/parsed_{ngfw_config}/{item}.cfg', mode='wt', encoding='utf-8') as myfile:
                myfile.write('\n'.join(parsed_config[item]))

    # -------- I N T E R F A C E S-----------------------------------------------------------------------------------
    # Sorted name interface
    interfaces = []
    for interface_line in parsed_config["interface"]:
        interface_line_dict = interface_line.split(' ')
        if ((interface_line.find("add interface ") != -1) or (interface_line.find("set interface ") != -1)):
            interfaces.append(interface_line_dict[2])
        elif (interface_line.find("set pim interface ") != -1):
            interfaces.append(interface_line_dict[3])

    interfaces = list(set(interfaces))
    try:
        interfaces.remove("lo")
    except:
        None
    interfaces = sorted(interfaces)

    # fill interfaces
    catalog_of_interfaces = []
    count_of_interfaces = 0
    for interface in interfaces:
        element = {
            "name": interface,
            "comments": "",
            "state": "",
            "type": "",
            "ipv4-address": "",
            "mask-length": "",
            "subnet-mask": ""
            }
        
        for interface_line in parsed_config["interface"]:
            if interface_line.find(interface) != -1 and interface_line:
                interface_line_dict = interface_line.split(' ')

                # set
                if interface_line_dict[0] == "set":

                    # set interface bond24.394 
                    if (interface_line_dict[1] == "interface" and 
                        interface_line_dict[2] == interface):
                            
                            # set interface bond24.394 state on
                            if interface_line_dict[3] == "state":
                                element["state"] = interface_line_dict[4]

                                # type: subinterface
                                if interface_line_dict[2].find('.') != -1:
                                    element["type"] = "subinterface"

                                # type: aggregation
                                elif interface_line_dict[2].find('bond') != -1:
                                    element["type"] = "aggregation"
                                
                                # type: physical
                                else:
                                    element["type"] = "physical"

                            # set interface eth2-02 comments "eth2-02-comment"
                            elif interface_line_dict[3] == "comments":
                                element["comments"] = interface_line_dict[4].replace("\"","")

                            # set interface eth2-04 auto-negotiation on
                            elif interface_line_dict[3] == "auto-negotiation":
                                element["auto-negotiation"] = interface_line_dict[4]

                            # set interface bond24.328 ipv4-address 10.10.155.3 mask-length 24
                            elif interface_line_dict[3] == "ipv4-address":
                                element["ipv4-address"] = interface_line_dict[4]

                                # mask & masklength
                                if interface_line_dict[5] == "mask-length":
                                    element["mask-length"] = interface_line_dict[6]
                                    element["subnet-mask"] = str(ip_network(f'0.0.0.0/{interface_line_dict[6]}').netmask)
                                
                                elif interface_line_dict[5] == "subnet-mask":
                                    element["subnet-mask"] = interface_line_dict[6]
                                    element["mask-length"] = str(ip_network(f'0.0.0.0/{interface_line_dict[6]}').prefixlen)
                            
                            # set interface eth2-01 link-speed 1000M/full
                            elif interface_line_dict[3] == "link-speed":
                                element["link-speed"] = interface_line_dict[4]

                            # set interface eth2-02 mtu 1500
                            elif interface_line_dict[3] == "mtu":
                                element["mtu"] = interface_line_dict[4]

                            # set interface eth3-01 rx-ringsize 2048
                            elif interface_line_dict[3] == "rx-ringsize":
                                element["rx-ringsize"] = interface_line_dict[4]

                            # set interface eth3-01 tx-ringsize 2048
                            elif interface_line_dict[3] == "tx-ringsize":
                                element["tx-ringsize"] = interface_line_dict[4]

                            # set interface bond24.394 ?
                            else:
                                print(interface_line)

                    # set pim interface bond13.124 
                    elif (interface_line_dict[1] == "pim" and
                          interface_line_dict[2] == "interface" and
                          interface_line_dict[3] == interface):
                        
                        # set pim interface bond13.124 virtual-address on
                        if interface_line_dict[4] == "virtual-address":
                            element["virtual-address"] = interface_line_dict[5]
                        
                        # set pim interface bond13.114 on
                        else:
                            element["pim"] = interface_line_dict[4]

                    # set igmp interface eth2-02.511 
                    elif (interface_line_dict[1] == "igmp" and 
                          interface_line_dict[2] == "interface" and
                          interface_line_dict[3] == interface):
                        element["igmp"] = interface_line_dict[6]
                        element["local-group"] = interface_line_dict[5]

                # add
                elif (interface_line_dict[0] == "add"):

                    # add interface bond24 vlan 328
                    if (interface_line_dict[1] == "interface" and
                        interface_line_dict[2] == interface and
                        interface_line_dict[3] == "vlan"):
                        try:
                            element["vlans"].append(interface_line_dict[4])
                        except:
                            element["vlans"] = [interface_line_dict[4]]

                    # add bonding group 13 interface eth3-01
                    elif (interface_line_dict[1] == "bonding" and
                          interface_line_dict[2] == "group" and
                          interface_line_dict[4] == "interface" and
                          interface_line_dict[5] == interface):
                        element["member"] = f"bond{interface_line_dict[3]}"

                    # add ?
                    else:
                        print(interface_line)

                # ?
                else:
                    print(interface_line)

        if element:

            # add members to aggregations interface
            if element['type'] == "aggregation":
                members = []
                aggregation = {}
                for interface_line in parsed_config["interface"]:
                    interface_line_dict = interface_line.split(' ')

                    if (interface_line.find("bonding group ") != -1 and 
                        interface == f"bond{interface_line_dict[3]}"):

                        # add bonding group 13 interface eth3-01
                        if (interface_line.find("add bonding group ") != -1 and 
                            len(list(filter(None, interface_line_dict))) > 4):
                            members.append(interface_line_dict[5])

                        # set bonding group 13 
                        elif (interface_line.find("set bonding group ") != -1):

                            # set bonding group 13 mode 8023AD 
                            if interface_line_dict[4] == "mode":
                                aggregation["mode"] = interface_line_dict[5]

                            # set bonding group 13 down-delay 200 
                            elif interface_line_dict[4] == "down-delay":
                                aggregation["down-delay"] = interface_line_dict[5]

                            # set bonding group 13 lacp-rate slow 
                            elif interface_line_dict[4] == "lacp-rate":
                                aggregation["lacp-rate"] = interface_line_dict[5]

                            # set bonding group 13 mii-interval 100
                            elif interface_line_dict[4] == "mii-interval":
                                aggregation["mii-interval"] = interface_line_dict[5]

                            # set bonding group 13 up-delay 100 
                            elif interface_line_dict[4] == "up-delay":
                                aggregation["up-delay"] = interface_line_dict[5]

                            # set bonding group 13 xmit-hash-policy layer2 
                            elif interface_line_dict[4] == "xmit-hash-policy":
                                aggregation["xmit-hash-policy"] = interface_line_dict[5]

                            # ? bonding group 13 ?
                            else:
                                print(interface_line)

                element['members'] = members
                element['aggregation'] = aggregation

            catalog_of_interfaces.append(element)
            count_of_interfaces += 1

    # Output
    output_of_interfaces = {
        "total": count_of_interfaces,
        "objects": catalog_of_interfaces
    }
    with open(f'{path["output_path"]}/parsed_{ngfw_config}/interface_parsed.json', mode='w') as myfile:
        json.dump(output_of_interfaces, myfile, sort_keys = True, indent = 4, ensure_ascii = False)
    logger.success(f"For config {ngfw_config}, information about interfaces is recorded")

    # -------- R O U T E S-----------------------------------------------------------------------------------
    # sorted routes
    name_routes = []
    count_of_routes = 0
    for static_route_line in parsed_config["static_route"]:
        static_route_line_dict = static_route_line.split(' ')
        name_routes.append(static_route_line_dict[2])

    name_routes = list(set(name_routes))
    name_routes = sorted(name_routes)

    catalog_of_routes = []
    count_of_routes = 0

    for name_route in name_routes:
            
        parsed_static_route = {
            "destination": name_route,
            "enabled": "",
            "address":  "",
            "logical": "auto",
            "priority": "",
            "rank": 60,
            "comment": ""
        }

        for static_route_line in parsed_config["static_route"]:
            static_route_line_dict = static_route_line.split(' ')
            if static_route_line_dict[2] == name_route:

                # priority
                if static_route_line.find("priority") != -1:
                    parsed_static_route["priority"] = static_route_line_dict[static_route_line_dict.index("priority")+1]

                # rank
                if static_route_line.find("rank") != -1:
                    parsed_static_route["rank"] = static_route_line_dict[static_route_line_dict.index("rank")+1]

                # comment
                if static_route_line.find("comment") != -1:
                    parsed_static_route["comment"] = static_route_line[static_route_line.find("comment")+8:].replace("\"","")

                # address 
                if (static_route_line_dict[3] == "nexthop" and 
                    static_route_line_dict[4] == "gateway" and 
                    static_route_line_dict[5] == "address"):
                    parsed_static_route["address"] = static_route_line_dict[static_route_line_dict.index("address")+1]
                    parsed_static_route["enabled"] = static_route_line_dict[-1]

                # logical 
                if (static_route_line_dict[3] == "nexthop" and 
                    static_route_line_dict[4] == "gateway" and 
                    static_route_line_dict[5] == "logical"):
                    parsed_static_route["logical"] = static_route_line_dict[static_route_line_dict.index("logical")+1]
                    parsed_static_route["enabled"] = static_route_line_dict[-1]

        catalog_of_routes.append(parsed_static_route)
        count_of_routes += 1

    # Output
    output_of_routes = {
        "total": count_of_routes,
        "objects": catalog_of_routes
    }
    with open(f'{path["output_path"]}/parsed_{ngfw_config}/static_route_parsed.json', mode='w') as myfile:
        json.dump(output_of_routes, myfile, sort_keys = True, indent = 4, ensure_ascii = False)
    logger.success(f"For config {ngfw_config}, information about static routes is recorded")

    # -------- A R P - P R O X Y-----------------------------------------------------------------------------------
    catalog_arp_proxy = []
    count_arp_proxy = 0
    for arp_proxy_line in parsed_config["arp"]:
        arp_proxy_line_dict = arp_proxy_line.split(' ')
        parsed_arp_proxy = {
            "address": arp_proxy_line_dict[4],
            "interface": arp_proxy_line_dict[6],
            "real_address": arp_proxy_line_dict[8]
        }
        catalog_arp_proxy.append(parsed_arp_proxy)
        count_arp_proxy += 1

    # Output
    output_of_arp = {
        "total": count_arp_proxy,
        "objects": catalog_arp_proxy
    }
    with open(f'{path["output_path"]}/parsed_{ngfw_config}/arp_parsed.json', mode='w') as myfile:
        json.dump(output_of_arp, myfile, sort_keys = True, indent = 4, ensure_ascii = False)
    logger.success(f"For config {ngfw_config}, information about arp-proxy is recorded")

    # -------- P B R-----------------------------------------------------------------------------------






