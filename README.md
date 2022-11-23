# Arista CloudVision Portal - Actions

# Conventions
Each action shall be created as both an Action-Pack and an Action. These are functionally eqivelent.
Each action-pack consists of a folder containing the required yaml files, and a script.py.

The Action folder contains the yaml and the script in question.

# Action-Pack vs. Action
In CVP 2021.3.0 there were 2 major changes for Custom Actions.
1. Move to Python3
2. Replacement of the cvplibrary with a ctx object

As the context object and the cvplibrary are mutually exclusive, we have the Actions for CVP < 2021.3.0, and the Action-Pack for CVP 2021.3.0+


## Installation of Action-Pack
* `tar` up the action pack while you are in the actionpacks directory (or equivalent directory). The name of the tar is not important, but it is good practice to use the same name as the as the directory you are tarring, and include the version string.
* Use scp to copy the tar file over to any of the cvp nodes in the system.
* On the cvp node, upload the action pack via the the actionpack_cli tool

*Note*: This will upload the action pack as the aerisadmin user, which means that only the aerisadmin user will be able to modify or delete them (copies can still be made and modified/deleted by any user authorised to create actions).

## Installation of Action
Copy the python script and associated yml file to CVP and run the following
`/cvpi/tools/script-util upload -path /tmp/cvp-device-health-check.py  -config /tmp/cvp-device-health-check.yaml`

### Update/Removal of Action
To update the script, the existing version must be removed first (if they have the same name):
`/cvpi/tools/script-util remove -name "Switch Healthcheck"`
and then the new version can be installed


# CVP Actions
## Device Healthcheck
Can be applied to one or more devices. Will fail / trigger an assert if any of the test cases fail.
## Cleanup Flash
Backport of [Delete SWIs](https://github.com/aristanetworks/cloudvision-python-actions/tree/trunk/delete-swis-action-pack/delete-swis). Deletes all unused swi files.
## Advanced Image Staging
Pre-stage the required software images to a switch, in advance of the upgrade itself. Assumes that the image bundle has
already been updated.

# References
[UI For Custom Action Scripts](https://www.arista.com/en/support/toi/cvp-2021-3-0/14901-ui-for-custom-action-scripts)

[Change Control Scripted Actions](https://www.arista.com/en/support/toi/cvp-2019-1-0/14330-change-control-script-actions)

# Other Action Packs
[CloudVision Python Actions](https://github.com/aristanetworks/cloudvision-python-actions)
