#!/usr/bin/python
# Copyright (c) 2022 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.

# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,  this list of conditions and the following disclaimer in the documentation 
#   and/or other materials provided with the distribution.
# * Neither the name of the Arista nor the names of its contributors may be used to endorse or promote products derived from this software without 
#   specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.
#
# Version 1.0: 23/11/2022
# Advanced Software Image Staging


import json
import ssl
from requests import get

SCRIPT_DEBUG = False

ssl._create_default_https_context = ssl._create_unverified_context


"""
CVP_USERNAME - Username of the current user
CVP_PASSWORD - Password of the current user
CVP_IP - IP address of the current device (not the CVP IP)
CVP_MAC - MAC of the current device
CVP_SERIAL - Serial number of the current device
CVP_SESSION_ID - Session id of current cvp user, this can be passed around to cvp api
SCRIPT_ARGS - A dictionary of arguments passed to the Script Action
"""


def check_connection(hostname, device):
    """
    check_connection - make sure we can talk to the switch

    Args:
        hostname (str): the hostname of the device
        device (obj): The cvplibrary device object

    Returns:
        True if the device is reachable and we can use the API,
        False if not
    """
    try:
        response = device.runDeviceCmds(['show version'])
        if isinstance(response, list):
            if 'version' in response[0]['response']:
                return True
        else:
           ctx.alog("%s: Failed to connect to device. Error: %s - %s" % (hostname, response['errorCode'],response['errorMessage']) )

        return False

    except:
        ctx.alog("%s: We have reached an impossible state." % hostname)
        return None


def get_hostname(device):
    """
    get_hostname - get the hostname of the switch

    Args:
        device (obj): The cvplibrary device object

    Returns:
        str - the hostname, if successful, None if not
    """
    try:
        response = device.runDeviceCmds(['show hostname'])
        return response[0]['response']['hostname']
    except:
        return None


def get_bootImage(device):
    """
    get_bootImage - get the current boot image

    Args:
        device (obj): The cvplibrary device object

    Returns:
        str - the bootimage, if successful, None if not
        Will be of the structure "flash:EOS-4.21.1F.swi"

    Notes:
        Always includes the "flash:" in the response
    """
    try:
        response = device.runDeviceCmds(['show boot-config'])
        return response[0]['response']['softwareImage']
    except:
        return None


def get_files(device):
    """
    get_files - get a list of the names of the files in flash:

    Args:
        device (obj): The cvplibrary device object

    Returns:
        List(str) - A list of strings, each being the name of a file in
        flash: (/mnt/flash)

    Notes:
        None
    """
    try:
        response = device.runDeviceCmds(['enable','dir flash:'])
        ctx.alog('File system contains: %s' % response)
        semi_parsed = response[1]['response']['messages'][0].split('\n')

        file_list = []
        for line in semi_parsed[2:]:
            if len(line.split()) > 0:
                file_list.append(line.split()[-1])

        return file_list

    except Exception as e:
        ctx.alog("ERROR ERROR: %s" % str(e))
        return None


def get_cvp(device):
    """
    get_cvp - use the device configuration to figure out how to talk to CVP

    Args:
        device (obj): The cvplibrary device object

    Returns:
        cvp (str), vrf(str) - the IP address or hostname of CVP, and the name
        of the vrf used (default if not)

    Notes:
        None
    """
    cvp = ""
    vrf = "default"
    response = device.runDeviceCmds(['show running-config section daemon'], fmt='text')

    if len(response[0]['error']) != 0:
        return None,None

    output_string = response[0]['response']['output']
    daemon_list = output_string.split('daemon ')[1:]

    if len(daemon_list) == 0:
        ctx.alog('Error parsing daemon config: %s' % output_string)
        return None,None

    for entry in daemon_list:
        lines = entry.split('\n')
        ctx.alog('')
        if 'exec' in lines[1] and 'TerminAttr' in lines[1]:
            ctx.alog('get_cvp - TerminAttr config located')
            parsed = lines[1].split()
            for element in parsed:
                if SCRIPT_DEBUG:
                    ctx.alog('get_cvp - Currently parsing: %s' % element)
                if 'cvaddr' in element or 'cvvrf' in element:
                    if 'cvaddr' in element and cvp == "":
                        cvp = element.split('=')[1].split(':')[0]
                    else:
                        vrf = element.split('=')[1]
            return cvp, vrf
    # Return defaults if not found
    return cvp,vrf


def get_image_bundles(cvp_ip):
    """
    get_image_bundles - get the details of the image bundles stored on CVP

    Args:
        cvp_ip (str): The IP address of hostname of CVP

    Returns:
        data(list) - A list of dicts with the image bundle information

    Notes:
        None
    """
    url = "https://" + cvp_ip + "/cvpservice/image/getImageBundles.do?queryparam=&startIndex=0&endIndex=0"
    session_id = ctx.user.token

    response = get(url, cookies= {'access_token':session_id},verify=False)
    data = response.json()['data']

    ctx.alog("Image bundle data returned is: %s" % data)

    return data


def get_assigned_image(cvp_ip, mac_address):
    """
    get_assigned_image - get the image bundle currently assigned to a switch

    Args:
        cvp_ip (str): The IP address of hostname of CVP
        mac_address (str): The MAC address of the switch to lookup

    Returns:
        data(list) - A list of dicts with the image bundle information

    Notes:
        None
    """
    url = "https://" + cvp_ip + "/cvpservice/provisioning/getNetElementInfoById.do?netElementId=" + mac_address
    session_id = ctx.user.token

    response = get(url, cookies= {'access_token':session_id},verify=False)
    ctx.alog("%s" % response)
    data = response.json()

    if SCRIPT_DEBUG:
        ctx.alog("Query url is: %s" % url)
        ctx.alog("Response to device query: %s" % data)

    return data


def stage_files(device, cvp_ip, file_list, vrf="default"):
    """
    stage_files - Copy the files to the switch

    Args:
        device (obj): The cvplibrary device object
        cvp_ip (str): The IP address of hostname of CVP
        file_list(list): A list of the file names to be transferred
        vrf (str): The VRF the switch should use to reach CVP

    Returns:
        True if the transfer was successful, False if not

    Notes:
        The switch is pulling the image from CVP rather then a push action.
        This allows install source to be used for the EOS image, since that would
        install the image on both supervisors on a dual-sup system.
    """
    commands = ["enable", "cli vrf " + vrf]
    errors = []
    for entry in file_list:

        try:
            if entry.endswith('.swi'):
                commands.append('install source https://' + cvp_ip + '/cvpservice/image/getImagebyId/' + entry)
                ctx.alog("Executing commands: %s" % commands)
                response = device.runDeviceCmds(commands)
                ctx.alog("%s" % response)
                for x in response:
                    if len(x['error']) > 0:
                        errors.append(x['error'])
                commands.remove('install source https://' + cvp_ip + '/cvpservice/image/getImagebyId/' + entry)
            else:
                commands.append('copy https://' + cvp_ip + '/cvpservice/image/getImagebyId/' + entry + ' flash:')
                ctx.alog("Executing commands: %s" % commands)
                response = device.runDeviceCmds(commands)
                ctx.alog("%s" % response)
                for x in response:
                    if len(x['error']) > 0:
                        errors.append(x['error'])
                commands.remove('copy https://' + cvp_ip + '/cvpservice/image/getImagebyId/' + entry + ' flash:')
        except Exception as e:
            ctx.alog("Error in file transfer: %s" % e)
            return False

    if len(errors) > 0:
        ctx.alog("The following errors occurred: %s" % errors)
        return False

    return True


def restore_boot(device, boot_image):
    """
    resture_boot - reset the boot-image back to original

    Args:
        device (obj): The cvplibrary device object
        boot_image(str): The string of the original boot image (including the 'flash:')

    Returns:
        True if successful, False if not
    """
    try:
        command = 'boot system ' + boot_image
        response = device.runDeviceCmds(['enable','configure terminal',command])
        if len(response[0]['error']) == 0:
            return True
        else:
            return False
    except:
        return False


def main():
    username = ctx.user.username
    password = ctx.user.token
    ip = ctx.getDevice().ip
    serial = ctx.getDevice().id
    mac = ctx.getDevice().mac

    if SCRIPT_DEBUG:
        cvx.alog("Context loaded for IP: %s, serial: %s, mac: %s" % (ip, serial, mac))

    ctx.alog("Advanced image staging v1.0")
    if not check_connection(serial, ctx):
        ctx.alog("%s: Connection failed." % serial)
        assert False

    hostname = get_hostname(ctx)
    if hostname is None:
        hostname = serial

    current_boot = get_bootImage(ctx)
    if current_boot is None:
        ctx.alog("%s: Unable to determine boot image" % hostname)
        assert False

    cvp_ip, vrf = get_cvp(ctx)
    if cvp_ip is None:
        ctx.alog('%s: Unable to determine CVP IP' % hostname)
        assert False
    ctx.alog('%s: CVP IP: %s in VRF: %s' % (hostname, cvp_ip, vrf))


    assigned_image = get_assigned_image(cvp_ip, mac)
    ctx.alog("Current boot image is: %s" % current_boot)
    ctx.alog("CVP assigned image bundle is: %s" % assigned_image['bundleName'])


    if assigned_image['bundleName'] is not None:
        # We have an image assigned, so we need to get the file names
        server_images = get_image_bundles(cvp_ip)
        if SCRIPT_DEBUG:
            ctx.alog("Server image bundles are: %s" % server_images)

        pending_files = []
        for bundle in server_images:
            if bundle['key'] == assigned_image['imageBundleId']:
                pending_files = bundle['imageIds']

        if len(pending_files) > 0:
            ctx.alog("%d files in the bundle" % len(pending_files))
            # Is the file already there?
            flash = get_files(ctx)
            if flash is None:
                ctx.alog("%s: Unable to identify flash contents")
                assert False

            if SCRIPT_DEBUG:
                ctx.alog('%s: Flash contains the following;\n%s' % (hostname,flash))

            for existing_file in flash:
                if existing_file in pending_files:
                    pending_files.remove(existing_file)

            if len(pending_files) > 0:
                ctx.alog("%s: The following files are to be staged: %s" % (hostname, pending_files))
                response = stage_files(ctx, cvp_ip, pending_files, vrf)

                if response:
                    ctx.alog('Successfully staged files. Preserving existing boot image.')
                    resp = restore_boot(ctx, current_boot)
                    if resp:
                        ctx.alog('%s: Staging completed, and boot image presrved' % hostname)
                    else:
                        ctx.alog('%s: Unable to reset boot image to %s' % (hostname, current_boot))
                        assert False
                else:
                    ctx.alog('%s: Failed to stage files' % hostname)
                    assert False

            else:
                ctx.alog("%s: Files already staged. Nothing to do" % hostname)

        else:
            ctx.alog("Nothing to transfer, no files in bundle")
    else:
        ctx.alog("No image bundle assigned")

    return 0


if __name__ == '__main__':
    main()