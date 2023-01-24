import os
from lxml import etree

actions = {
"2uX4OwcwTBOe7y66y27kxw==": "Execute command line / URL",
"tkamn96US7mbrjykfswQ6g==": "Change trigger on/off state",
"/UFV1XmPRPqrifL4cO+UuA==": "Open database file",
"9VdhS/hMQV2pE3o5zRDwvQ==": "Save active database",
"Iq135Bd4Tu2ZtFcdArOtTQ==": "Synchronize active database with a file/URL",
"gOZ/TnLxQEWRdh8sI9jsvg==": "Import into active database",
"D5prW87VRr65NO2xP5RIIg==": "Export active database",
"W79FnVS/Sb2X+yzuX5kKZw==": "Close active database",
"P7gzLdYWToeZBWTbFkzWJg==": "Activate database (select tab)",
"Oz0+MeSzQqa6zNXAO6ypaQ==": "Wait",
"CfePcyTsT+yItiXVMPQ0bg==": "Show message box",
"QGmlNlcbR5Kps3NlMODPww==": "Perform global auto-type",
"MXCPrWSTQ/WU7sgaI24yTQ==": "Perform auto-type with selected entry",
"Qug3gXPTTuyBSJ47NqyDhA==": "Show entries by tag",
"lYGPRZlmSYirPoboGpZoNg==": "Add custom toolbar button",
"1m1BomyyRLqkSApB+glIeQ==": "Remove custom toolbar button",
}

# My best guess, maybe more actions can be misused, i guess
dangerours_actions = {
"Iq135Bd4Tu2ZtFcdArOtTQ==",
"2uX4OwcwTBOe7y66y27kxw==",
"D5prW87VRr65NO2xP5RIIg=="
}

# My best guess, maybe more actions can be misused, i guess
important_policies = {
    "ExportNoKey",
}

print('CVE-2029-24055 Scanner')
print('======================')
print('Warning!')
print('This tool is a dirty hack, but works for me. If you want more, have fun!')
print('No functionality is guaranteed! Use at your own risk!')
print('======================')
if os.name != 'nt':
    print('Sorry, this tool works only under Windows!')
    exit(1)

# Get path to default config
config_file=os.getenv('APPDATA')+"\KeePass\KeePass.config.xml"
print(f"Reading from this config file: {config_file}")

# Read Config
tree = etree.parse(config_file)
root = tree.getroot()

# parse trough all Triggers
print("--- Trigger:")
for trigger in root.findall("./Application/TriggerSystem/Triggers/"):
    # Now process each found trigger
    # print(f" ID  : {trigger.find('Guid').text}")
    print(f" Name: {trigger.find('Name').text}")

    for TypeGUID in trigger.findall("./Actions/Action/"):
        try:
            if TypeGUID.text in dangerours_actions:
                print(f" Action: {actions[TypeGUID.text]}  !!!!!! DANGEROUS !!!!!")
            else:
                print(f" Action: {actions[TypeGUID.text]}")
        except:
            pass

print("--- Policies:")
# Check for ExportNoKey
for policy in root.findall("./Security/Policy/"):
    if policy.tag in important_policies:
        print(f" Policy {policy.tag}: {policy.text}")