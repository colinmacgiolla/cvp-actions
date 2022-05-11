# Copyright (c) 2022 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the COPYING file.
#
# Version 1.0: 17-01-2022
# EOS Device Healthchecks as Custom CVP Task

"""
CVP_USERNAME - Username of the current user
CVP_PASSWORD - Password of the current user
CVP_IP - IP address of the current device (not the CVP IP)
CVP_MAC - MAC of the current device
CVP_SERIAL - Serial number of the current device
CVP_SESSION_ID - Session id of current cvp user, this can be passed around to cvp api
SCRIPT_ARGS - A dictionary of arguments passed to the Script Action
"""

from cvplibrary import CVPGlobalVariables, GlobalVariableNames
from cvplibrary import RestClient
from cvplibrary import Device
from cvplibrary.auditlogger import alog
import json
import ssl
import ipaddress

ssl._create_default_https_context = ssl._create_unverified_context
SCRIPT_DEBUG = False
SPINE_HINT = 'spine'
UNDERLAY_VRF = 'default'


def check_connection(serial, device):
    try:
        response = device.runCmds(['show version'])
        if isinstance(response, list):
            if 'version' in response[0]['response']:
                return True
        else:
           alog("%s: Failed to connect to device. Error: %s - %s" % (serial, response['errorCode'],response['errorMessage']) )

        return False

    except:
        alog("%s: We have reached an impossible state." % serial)
        return None


def get_hostname(device):
    try:
        response = device.runCmds(['show hostname'])
        return response[0]['response']['hostname']
    except:
        return None



# Report unapproved EOS versions. Update list as required.
def verify_eos_version(device):
    try:
        response = device.runCmds(['show version'])
        if response[0]['response']['version'] in ['4.25.4M', '4.26.1F']:
            return True
        else:
            return False
    except:
        return None


# Report unapproved TerminAttr versions. Update list as required.
def verify_terminattr_version(device):
    try:
        response = device.runCmds(['show version detail'])
        if response[0]['response']['details']['packages']['TerminAttr-core']['version'] in ['v1.13.6', 'v1.15.2']:
            return True
        else:
            return False
    except:
        return None


# Report mismatch in installed and boot extensions.
def verify_extensions(device):
    try:
        response = device.runCmds(['show extensions', 'show boot-extensions'])
        installed_extensions = []
        boot_extensions = []
        for extension in response[0]['response']['extensions']:
            if response[0]['response']['extensions'][extension]['status'] == 'installed':
                installed_extensions.append(extension)
        for extension in response[1]['response']['extensions']:
            extension = extension.strip('\n')
            if extension == '':
                pass
            else:
                boot_extensions.append(extension)
        installed_extensions.sort()
        boot_extensions.sort()
        if installed_extensions == boot_extensions:
            return True
        else:
            return False
    except:
        return None


# Report Aboot versions affected by field notice 44.
def verify_field_notice_44(device):
    try:
        response = device.runCmds(['show version detail'])
        devices = ['DCS-7010T-48',
                   'DCS-7010T-48-DC',
                   'DCS-7050TX-48',
                   'DCS-7050TX-64',
                   'DCS-7050TX-72',
                   'DCS-7050TX-72Q',
                   'DCS-7050TX-96',
                   'DCS-7050TX2-128',
                   'DCS-7050SX-64',
                   'DCS-7050SX-72',
                   'DCS-7050SX-72Q',
                   'DCS-7050SX2-72Q',
                   'DCS-7050SX-96',
                   'DCS-7050SX2-128',
                   'DCS-7050QX-32S',
                   'DCS-7050QX2-32S',
                   'DCS-7050SX3-48YC12',
                   'DCS-7050CX3-32S',
                   'DCS-7060CX-32S',
                   'DCS-7060CX2-32S',
                   'DCS-7060SX2-48YC6',
                   'DCS-7160-48YC6',
                   'DCS-7160-48TC6',
                   'DCS-7160-32CQ',
                   'DCS-7280SE-64',
                   'DCS-7280SE-68',
                   'DCS-7280SE-72',
                   'DCS-7150SC-24-CLD',
                   'DCS-7150SC-64-CLD',
                   'DCS-7020TR-48',
                   'DCS-7020TRA-48',
                   'DCS-7020SR-24C2',
                   'DCS-7020SRG-24C2',
                   'DCS-7280TR-48C6',
                   'DCS-7280TRA-48C6',
                   'DCS-7280SR-48C6',
                   'DCS-7280SRA-48C6',
                   'DCS-7280SRAM-48C6',
                   'DCS-7280SR2K-48C6-M',
                   'DCS-7280SR2-48YC6',
                   'DCS-7280SR2A-48YC6',
                   'DCS-7280SRM-40CX2',
                   'DCS-7280QR-C36',
                   'DCS-7280QRA-C36S']
        variants = ['-SSD-F',
                    '-SSD-R',
                    '-M-F',
                    '-M-R',
                    '-F',
                    '-R']
        model = response[0]['response']['modelName']
        for variant in variants:
            model = model.replace(variant, '')
        if model not in devices:
            return None
        else:
            for component in response[0]['response']['details']['components']:
                if component['name'] == 'Aboot':
                    aboot_version = component['version'].split('-')[2]
            if aboot_version.startswith('4.0.') and int(aboot_version.split('.')[2]) < 7:
                return False
            elif aboot_version.startswith('4.1.') and int(aboot_version.split('.')[2]) < 1:
                return False
            elif aboot_version.startswith('6.0.') and int(aboot_version.split('.')[2]) < 9:
                return False
            elif aboot_version.startswith('6.1.') and int(aboot_version.split('.')[2]) < 7:
                return False
            else:
                return True
    except:
        return None


# Report third party transceivers.
def verify_inventory(device):
    try:
        response = device.runCmds(['show inventory'])
        for interface in response[0]['response']['xcvrSlots']:
            if response[0]['response']['xcvrSlots'][interface]['mfgName'] not in ['Not Present', 'Arista Networks', 'Arastra, Inc.']:
                return False
        return True
    except:
        return None


# Report ZeroTouch mode enabled.
def verify_zerotouch(device):
    try:
        response = device.runCmds(['show zerotouch'])
        if response[0]['response']['mode'] == 'disabled':
            return True
        else:
            return False
    except:
        return None


# Report running-config startup-config differences.
def verify_running_config_diffs(device):
    try:
        response = device.runCmds(1,['enable','show running-config diffs'],'text')

        if len(response[1]['response']['output']) == 0:
            return True
        else:
            return False
    except:
        return None


# Report corefiles.
def verify_coredump(device):
    try:
        response = device.runCmds(['enable','bash timeout 10 ls /var/core'], 'text')
        if len(response[1]['response']['output'].split('\n')) == 1:
            return True
        else:
            return False
    except:
        return None


# Report suspicious agent logs.
def verify_agent_logs(device):
    try:
        response = device.runCmds(['show agent logs crash'], 'text')
        if len(response[0]['response']['output']) == 0:
            return True
        else:
            return False
    except:
        return None


# Report syslog errors (or lower) for last 7 days.
def verify_syslog(device):
    try:
        response = device.runCmds(['show logging last 7 days threshold warnings'], 'text')
        if len(response[0]['response']['output']) == 0:
            return True
        else:
            return False
    except:
        return None


# Report uptime below 24 hours.
def verify_uptime(device):
    try:
        response = device.runCmds(['show uptime'])
        if response[0]['response']['upTime'] > 86400:
            return True
        else:
            # If we reloaded in the last 24 hours, at a user request
            # Then this test case should pass (cover reload due to upgrade)
            if verify_reload_cause(device) is not True:
                return False
            else:
                return True
    except:
        return None


# Report reloads not initiated by the user.
def verify_reload_cause(device):
    try:
        response = device.runCmds(['show reload cause'])
        if response[0]['response']['resetCauses'][0]['description'] == 'Reload requested by the user.':
            return True
        else:
            return False
    except:
        return None


# Report system temperature alarms.
def verify_system_temperature(device):
    try:
        response = device.runCmds(['show system environment temperature'])
        if response[0]['response']['systemStatus'] != 'temperatureOk' and response[0]['response']['systemStatus'] != 'unknownTemperatureAlarmLevel':
            return False
        for slot in response[0]['response']['cardSlots']:
            for sensor in slot['tempSensors']:
                if sensor['hwStatus'] != 'ok' or sensor['alertCount'] != 0:
                    return False
        for slot in response[0]['response']['powerSupplySlots']:
            for sensor in slot['tempSensors']:
                if sensor['hwStatus'] != 'ok' or sensor['alertCount'] != 0:
                    return False
        for sensor in response[0]['response']['tempSensors']:
            if sensor['hwStatus'] != 'ok' or sensor['alertCount'] != 0:
                return False
        else:
            return True
    except:
        return None


# Report transceiver temperature alarms.
def verify_transceiver_temperature(device):
    try:
        response = device.runCmds(['show system environment temperature transceiver'])
        for sensor in response[0]['response']['tempSensors']:
            if sensor['hwStatus'] != 'ok' or sensor['alertCount'] != 0:
                return False
        return True
    except:
        return None


# Report cooling alarms.
def verify_environment_cooling(device):
    try:
        response = device.runCmds(['show system environment cooling'])
        if response[0]['response']['systemStatus'] != 'coolingOk' and response[0]['response']['systemStatus'] != 'unknownCoolingAlarmLevel':
            return False
        for slot in response[0]['response']['powerSupplySlots']:
            if slot['status'] != 'ok':
                return False
            for fan in slot['fans']:
                if fan['status'] != 'ok':
                    return False
        for slot in response[0]['response']['fanTraySlots']:
            if slot['status'] != 'ok':
                return False
            for fan in slot['fans']:
                if fan['status'] != 'ok':
                    return False
        else:
            return True
    except:
        return None


# Report power alarms.
def verify_environment_power(device):
    try:
        response = device.runCmds(['show system environment power'])
        for powersupply in response[0]['response']['powerSupplies']:
            if response[0]['response']['powerSupplies'][powersupply]['state'] != 'ok':
                return False
        return True
    except:
        return None


# Report CPU utilization over 75%.
def verify_cpu_utilization(device):
    try:
        response = device.runCmds(['show processes top once'])
        if response[0]['response']['cpuInfo']['%Cpu(s)']['idle'] > 25:
            return True
        else:
            return False
    except:
        return None


# Report memory utilization over 75%.
def verify_memory_utilization(device):
    try:
        response = device.runCmds(['show version'])
        if float(response[0]['response']['memFree']) / float(response[0]['response']['memTotal']) > 0.25:
            return True
        else:
            return False
    except:
        return None


# Report filesystem utilization over 75%.
def verify_filesystem_utilization(device):
    try:
        response = device.runCmds(['bash timeout 10 df -h'], 'text')
        for line in response[0]['response']['output'].split('\n')[1:]:
            if 'loop' not in line and len(line) > 0:
                if int(line.split()[4].replace('%', '')) > 75:
                    return False
        return True
    except:
        return None


# Report unsynchronised NTP.
def verify_ntp(device):
    try:
        response = device.runCmds(['show ntp status'], 'text')
        if response[0]['response']['output'].split('\n')[0].split(' ')[0] == 'synchronised':
            return True
        else:
            return False
    except:
        return None


# Report adverse drops.
def verify_adverse_drops(device):
    try:
        response = device.runCmds(['show hardware counter drop'])
        if response[0]['response']['totalAdverseDrops'] == 0:
            return True
        else:
            return False
    except:
        return None


# Report interface utilization over 75%.
def verify_interface_utilization(device):
    try:
        response = device.runCmds(['show interfaces counters rates'], 'text')
        for line in response[0]['response']['output'].split('\n')[1:]:
            if len(line) > 0:
                if line.split()[-5] == '-' or line.split()[-2] == '-':
                    pass
                elif float(line.split()[-5].replace('%', '')) > 75.0:
                    return False
                elif float(line.split()[-2].replace('%', '')) > 75.0:
                    return False
        return True
    except:
        return None


# Report interface errors.
def verify_interface_errors(device):
    try:
        response = device.runCmds(['show interfaces counters errors'])
        for interface in response[0]['response']['interfaceErrorCounters']:
            for counter in response[0]['response']['interfaceErrorCounters'][interface]:
                if response[0]['response']['interfaceErrorCounters'][interface][counter] != 0:
                    return False
        return True
    except:
        return None


# Report interface discards.
def verify_interface_discards(device):
    try:
        response = device.runCmds(['show interfaces counters discards'])
        for interface in response[0]['response']['interfaces']:
            for counter in response[0]['response']['interfaces'][interface]:
                if response[0]['response']['interfaces'][interface][counter] != 0:
                    return False
        return True
    except:
        return None


# Report error disabled interfaces.
def verify_interface_errdisabled(device):
    try:
        response = device.runCmds(['show interfaces status'])
        for interface in response[0]['response']['interfaceStatuses']:
            if response[0]['response']['interfaceStatuses'][interface]['linkStatus'] == 'errdisabled':
                return False
        return True
    except:
        return None


# Report inactive portchannel ports.
def verify_portchannels(device):
    try:
        response = device.runCmds(['show port-channel'])
        if len(response[0]['response']['portChannels']) == 0:
            return None
        else:
            for portchannel in response[0]['response']['portChannels']:
                if len(response[0]['response']['portChannels'][portchannel]['inactivePorts']) != 0:
                    return False
            return True
    except:
        return None


# Report illegal LACP packets.
def verify_lacp(device):
    try:
        response = device.runCmds(['show lacp counters all-ports'])
        if len(response[0]['response']['portChannels']) == 0:
            return None
        else:
            for portchannel in response[0]['response']['portChannels']:
                for interface in response[0]['response']['portChannels'][portchannel]['interfaces']:
                    if response[0]['response']['portChannels'][portchannel]['interfaces'][interface]['illegalRxCount'] != 0:
                        return False
            return True
    except:
        return None


# Report spanning-tree blocked ports.
def verify_spanning_tree_blocked_ports(device):
    try:
        response = device.runCmds(['show spanning-tree blockedports'])
        if len(response[0]['response']['spanningTreeInstances']) == 0:
            return True
        else:
            return False
    except:
        return None


# Report mismatch in operating and configured routing protocol model (ribd and multi-agent).
def verify_routing_protocol_model(device):
    try:
        response = device.runCmds([{'cmd': 'show ip route summary', 'revision': 3}])
        if response[0]['response']['protoModelStatus']['configuredProtoModel'] == response[0]['response']['protoModelStatus']['operatingProtoModel']:
            return True
        else:
            return False
    except:
        return None


# Report BFD peers in down state.
def verify_bfd(device):
    try:
        response = device.runCmds(['show bfd peers'])
        for neighbor in response[0]['response']['vrfs'][UNDERLAY_VRF]['ipv4Neighbors']:
            for interface in response[0]['response']['vrfs'][UNDERLAY_VRF]['ipv4Neighbors'][neighbor]['peerStats']:
                if response[0]['response']['vrfs'][UNDERLAY_VRF]['ipv4Neighbors'][neighbor]['peerStats'][interface]['status'] != 'up':
                        return False
        return True
    except:
        return None


# Report non-established BGP IPv4 unicast peers.
def verify_bgp_ipv4_unicast(device):
    try:
        response = device.runCmds(['show bgp ipv4 unicast summary vrf all'])
        if len(response[0]['response']['vrfs']) == 0:
            return None
        else:
            for vrf in response[0]['response']['vrfs']:
                for peer in response[0]['response']['vrfs'][vrf]['peers']:
                    if response[0]['response']['vrfs'][vrf]['peers'][peer]['peerState'] != 'Established':
                        return False
            return True
    except:
        return None


# Report non-established BGP EVPN peers.
def verify_bgp_evpn(device):
    try:
        response = device.runCmds(['show bgp evpn summary'])
        if len(response[0]['response']['vrfs'][UNDERLAY_VRF]['peers']) == 0:
            return None
        else:
            for peer in response[0]['response']['vrfs'][UNDERLAY_VRF]['peers']:
                if response[0]['response']['vrfs'][UNDERLAY_VRF]['peers'][peer]['peerState'] != 'Established':
                    return False
            return True
    except:
        return None


# Report MLAG errors.
def verify_mlag_status(device):
    try:
        response = device.runCmds(['show mlag'])
        if response[0]['response']['state'] == 'disabled':
            return None
        elif response[0]['response']['state'] != 'active':
            return False
        elif response[0]['response']['negStatus'] != 'connected':
            return False
        elif response[0]['response']['localIntfStatus'] != 'up':
            return False
        elif response[0]['response']['peerLinkStatus'] != 'up':
            return False
        else:
            return True
    except:
        return None


# Report MLAG interface errors.
def verify_mlag_interfaces(device):
    try:
        response = device.runCmds(['show mlag'])
        if response[0]['response']['state'] == 'disabled':
            return None
        elif response[0]['response']['mlagPorts']['Inactive'] != 0:
            return False
        elif response[0]['response']['mlagPorts']['Active-partial'] != 0:
            return False
        else:
            return True
    except:
        return None


def verify_mlag_config_sanity(device):
    try:
        response = device.runCmds(['show mlag config-sanity'])
        if response[0]['response']['mlagActive'] == False:
            # MLAG isn't running
            return None
        else:
            if len(response[0]['response']['globalConfiguration']) > 0 or \
                len(response[0]['response']['interfaceConfiguration']) > 0:
                return False
            else:
                return True
    except:
        return None



# Report VXLAN config-sanity errors.
def verify_vxlan_config_sanity(device):
    try:
        response = device.runCmds(['show vxlan config-sanity detail', 'show vlan dynamic'])
        if len(response[0]['response']['categories']) == 0:
            return None
        else:
            try:
                dynamic_vlans = response[1]['response']['dynamicVlans']['evpn']['vlanIds']
            except:
                dynamic_vlans = []
            for category in response[0]['response']['categories']:
                if category == 'localVtep':
                    for item in response[0]['response']['categories'][category]['items']:
                        if 'No remote VTEP in VLAN' in item['detail']:
                            if int(item['detail'].split()[5]) not in dynamic_vlans:
                                return False
                        elif item['detail'] == 'Virtual VTEP IP is not configured':
                            pass
                        elif item['checkPass'] is False:
                            return False
                elif category == 'mlag':
                    for item in response[0]['response']['categories'][category]['items']:
                        if item['detail'] == 'VLAN-VNI Mapping not identical':
                            pass
                        elif item['detail'] == 'No VTEP IP from peer':
                            pass
                        elif item['checkPass'] is False:
                            return False
                elif response[0]['response']['categories'][category]['allCheckPass'] is False:
                    return False
            return True
    except:
        return None


# Report IGMP snooping VLANs with traffic flooding.
def verify_igmp_snooping(device):
    try:
        response = device.runCmds(['show ip igmp snooping'])
        for vlan in response[0]['response']['vlans']:
            if response[0]['response']['vlans'][vlan]['igmpSnoopingState'] == 'enabled' and response[0]['response']['vlans'][vlan]['floodingTraffic'] is True:
                return False
        return True
    except:
        return None


# Report PIM interfaces with zero neighbors.
def verify_pim_neighbors(device):
    try:
        show_vrf = device.runCmds(['show vrf'])
        vrf_list = ['default']
        for vrf in show_vrf[0]['response']['vrfs']:
            vrf_list.append(vrf)
        for vrf in vrf_list:
            command = ['show ip pim vrf ' + vrf + ' interface']
            try:
                show_ip_pim_interface = device.runCmds(command)
                for interface in show_ip_pim_interface[0]['response']['interfaces']:
                    if 'Vlan' in interface:
                        pass
                    elif show_ip_pim_interface[0]['response']['interfaces'][interface]['neighborCount'] != 1:
                        return False
            except:
                pass
        return True
    except:
        return None


# Report freerunning PTP clock.
def verify_ptp_freerunning(device):
    try:
        response = device.runCmds(['show ptp'])
        if response[0]['response']['ptpMode'] != 'ptpBoundaryClock':
            return None
        elif response[0]['response']['ptpClockSummary']['gmClockIdentity'] == response[0]['response']['ptpClockSummary']['clockIdentity']:
            return False
        else:
            return True
    except:
        return None


# Report high PTP offset from master (1000 ns).
def verify_ptp_offset_from_master(device):
    try:
        response = device.runCmds(['show ptp monitor'])
        if response[0]['response']['ptpMode'] != 'ptpBoundaryClock':
            return None
        else:
            for data in response[0]['response']['ptpMonitorData']:
                if data['offsetFromMaster'] > 1000 or data['offsetFromMaster'] < -1000:
                    return False
            return True
    except:
        return None


# Report high PTP mean path delay (1000 ns).
def verify_ptp_mean_path_delay(device):
    try:
        response = device.runCmds(['show ptp monitor'])
        if response[0]['response']['ptpMode'] != 'ptpBoundaryClock':
            return None
        else:
            for data in response[0]['response']['ptpMonitorData']:
                if data['meanPathDelay'] > 1000:
                    return False
            return True
    except:
        return None


# Report high PTP skew.
def verify_ptp_skew(device):
    try:
        response = device.runCmds(['show ptp monitor'])
        if response[0]['response']['ptpMode'] != 'ptpBoundaryClock':
            return None
        else:
            for data in response[0]['response']['ptpMonitorData']:
                if data['skew'] > 1.1 or data['skew'] < 0.9:
                    return False
            return True
    except:
        return None


def verify_bgp_spine_prefixes(device):
    '''Spine prefix verification
    
       Details: This test case tries to ensure that we are getting consistent numbers
          of prefixes from all the spines. We attempt to do the following;
          1. Based on the SPINE_HINT global, we identify the spines from the LLDP neighbor name
            Specifically we identify the spine ports
          2. We take the routed interfaces, and get the IP addresses assigned to the spine ports
          3. Calculate the peer IP address (assumes there is only one)
          4. Retrieve the # of prefixes accepted for each of the spine peers
          5. Compare the # of prefixes over all the spines
          
       Args: device (obj)
             SPINE_HINT(str) (global) - string to search for in the hostname of the spines
             UNDERLAY_VRF(str) (global) - underlay VRF, default is "default"
       Returns:
          True (bool) - Test case has passed
          False (bool) - Test case failed
          None - Test was skipped
    '''

    try:
        neighbors = device.runCmds(['show lldp neighbors'])[0]['response']
        routed_interfaces = device.runCmds(['show ip interface brief'])[0]['response']
        peers = device.runCmds(['show ip bgp summary'])[0]['response']
        
        if SCRIPT_DEBUG:
            alog("Successfully collected interface info for verifying spine prefixes")
            
        if len(neighbors['lldpNeighbors']) == 0:
            if SCRIPT_DEBUG:
                alog("No LLDP neighbors found: %s" % neighbors)
            return None
        if len(routed_interfaces['interfaces']) == 0:
            if SCRIPT_DEBUG:
                alog("No routed interfaces found: %s" % routed_interfaces)
            return None
        if len(peers['vrfs'][UNDERLAY_VRF]['peers']) == 0:
            if SCRIPT_DEBUG:
                alog("No BGP peers found in default VRF: %s" % peers)
            return None
        
    except Exception as e:
        alog("verify_bgp_spine_prefixes: Data collection failed - %s" % e)
        return False
    
    # build a list of spine ports
    spine_ports = []
    for entry in neighbors['lldpNeighbors']:
        if SPINE_HINT in entry['neighborDevice'].lower():
            spine_ports.append(entry['port'])
    if SCRIPT_DEBUG:
        alog("Spine ports collected:\n%s" % spine_ports)

    if len(spine_ports) == 0:
        alog("No spine facing ports identified - skipping test")
        return None
                
    # Get the IP addresses of the spine links
    local_ip = []
    for entry in spine_ports:
        if entry in routed_interfaces['interfaces']:
            ip = routed_interfaces['interfaces'][entry]['interfaceAddress']['ipAddr']
            local_ip.append( ip['address'] + '/' + str(ip['maskLen']) )
            
    if SCRIPT_DEBUG:
        alog("Local port IP collected:\n%s" % local_ip)
        
    if len(local_ip) == 0:
        alog("Unable to identify local IP addresses for spine facing ports - skipping test")
        return None
            
    # Calculate the peer IPs
    peer_ip = []
    for address in local_ip:
        interface = ipaddress.IPv4Interface(address)
        hosts = list(interface.network.hosts())
        
        for entry in hosts:
            if entry != interface.ip:
                peer_ip.append( str(entry) )
            else:
                pass
    if SCRIPT_DEBUG:
        alog('Collected the following peer IPs:\n%s' % peer_ip)
    
    if len(peer_ip) == 0:
        alog("Unable to identify BGP peer IP addresses - skipping test")
        return None    
    
    # Check that we are receiving the same number of routes from all spines
    remote_prefixes = []
    for peer in peer_ip:
        remote_prefixes.append( peers['vrfs'][UNDERLAY_VRF]['peers'][peer]['prefixAccepted'] )
    if SCRIPT_DEBUG:
        alog('Spine prefixes accepted:\n%s' % remote_prefixes)
        
    if len(set(remote_prefixes)) == 1:
        return True
    else:
        alog('Not receiving or accepting the same number of prefixes from all spines.')
        return False

    # This code should be unreachable    
    return False



test_catalog = {
#    '01.01': verify_eos_version,
#    '01.02': verify_terminattr_version,
    '01.03': verify_extensions,
    '01.04': verify_field_notice_44,
    '01.05': verify_inventory,
    '01.06': verify_zerotouch,
    '01.07': verify_running_config_diffs,
    '01.08': verify_coredump,
    '01.09': verify_agent_logs,
    '01.10': verify_syslog,
    '01.11': verify_uptime,
    '01.12': verify_reload_cause,
    '01.13': verify_system_temperature,
    '01.14': verify_transceiver_temperature,
    '01.15': verify_environment_cooling,
    '01.16': verify_environment_power,
    '01.17': verify_cpu_utilization,
    '01.18': verify_memory_utilization,
    '01.19': verify_filesystem_utilization,
    '01.20': verify_ntp,
    '01.21': verify_adverse_drops,
    '02.01': verify_interface_utilization,
    '02.02': verify_interface_errors,
    '02.03': verify_interface_discards,
    '02.04': verify_interface_errdisabled,
    '02.05': verify_portchannels,
    '02.06': verify_lacp,
    '02.07': verify_spanning_tree_blocked_ports,
    '03.01': verify_routing_protocol_model,
    '03.02': verify_bfd,
    '03.03': verify_bgp_ipv4_unicast,
    '03.04': verify_bgp_evpn,
    '03.05': verify_mlag_status,
    '03.06': verify_mlag_interfaces,
    '03.07': verify_mlag_config_sanity,
    '03.08': verify_vxlan_config_sanity,
#    '03.09': verify_igmp_snooping,
#    '03.10': verify_pim_neighbors,
#    '03.11': verify_ptp_freerunning,
#    '03.12': verify_ptp_offset_from_master,
#    '03.13': verify_ptp_mean_path_delay,
#    '03.14': verify_ptp_skew,
    '03.15': verify_bgp_spine_prefixes,
}


def main():
    """
    CVP_USERNAME - Username of the current user
    CVP_PASSWORD - Password of the current user
    CVP_IP - IP address of the current device (not the CVP IP)
    CVP_MAC - MAC of the current device
    CVP_SERIAL - Serial number of the current device
    CVP_SESSION_ID - Session id of current cvp user, this can be passed around to cvp api
    SCRIPT_ARGS - A dictionary of arguments passed to the Script Action
    """

    username = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME)
    password = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD)
    ip = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP)


    switch = Device(CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP))
    serial = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_SERIAL)
    failures = False


    if not check_connection(serial, switch):
        alog("%s: Connection failed." % serial)
        assert False

    hostname = get_hostname(switch)
    if hostname is not None:
        serial = hostname


    # Create dict for test results
    test_summary = {}
    test_summary[serial] = {}
    alog("%s: Starting test case execution..." % serial)
    for test in sorted(test_catalog):
        # Run test cases
        if SCRIPT_DEBUG:
            alog("%s: Running test: %s" % (serial, test) )
        test_summary[serial][test] = test_catalog[test](switch)
        if SCRIPT_DEBUG:
            alog("%s: Test %s, result: %s" % (serial, test, test_summary[serial][test]) )


    # Check results
    for device in test_summary:
        for test, result in test_summary[device].items():
            if result is False:
                failures = True
                alog("%s: Failed health check - %s" % (serial, test_catalog[test].__name__))


    # If we had any failed tests assert to fail the action
    if failures:
        assert False



if __name__ == '__main__':
    main()




