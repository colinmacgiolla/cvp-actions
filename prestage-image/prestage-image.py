 # Copyright (c) 2022 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the COPYING file.
#
# Version 1.0: 11/05/2022
# Pre-stage software images

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
from urllib.parse import urljoin
import ssl

ssl._create_default_https_context = ssl._create_unverified_context
SCRIPT_DEBUG = False


def get_hostname(device):
    try:
        response = device.runCmds(['show hostname'])
        return response[0]['response']['hostname']
    except:
        return None








def main():
    switch = Device(CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP))
    serial = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_SERIAL)
    mac = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_MAC)
    
    hostname = get_hostname(switch)
    if hostname is not None:
        pass
    else:
        hostname = serial
    
    alog("%s: Prestage Image v1.0" % hostname)
    
    
    
    
    return 0




if __name__ == '__main__':
    main()
