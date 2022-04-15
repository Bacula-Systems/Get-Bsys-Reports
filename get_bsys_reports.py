#!/usr/bin/python3

# 20220406 - waa - Initial notes and ideas
# ----------------------------------------
#
# - Command line options... --all (DIR, and all SDs), --dir (Just the DIR), --sds (All SDs), SD,SD,SD (specific SDs)
# - Get Dir name from `s dir`
# - Will need to ask bconsole `.storage` to get all storages
#   defined, then filter for same IPs/FQDNs because multiple
#   Director Storage resources can point to the same SD server
# - Loop through systems on command line and/or determined from
#   config and then do the following:
#   - scp the defined bsysreport.pl script (configurable) to each
#     system
#   - Using ssh, then remotely run the script, capturing the name
#     of the file it will write to from its output
#   - When the script finishes, scp the report back to a local
#     tmp xxxx directory, renaming it to include the Director,
#     or Storage resource's name - or the Address = name, or other.
#     I need to think more on this.
#   - When all hosts have been contacted and the script outputs
#     have been downloaded, tar/gzip them using a local system name
#     and timestamp. Tgz file name might use some variable too.
#
# -----------------------------------------------------------------
#
# Need to install 'fabric' module via pip:
# sudo pip3 install fabric
#
# Set some variables specific to the local environment
# ----------------------------------------------------
#
# Define the ssh user to use when connecting to remote systems
# ------------------------------------------------------------
user = 'root'

# Define the bconsole program and config file locations
# -----------------------------------------------------
# bc_bin = '/opt/bacula/bin/bconsole'
# bc_cfg = '/opt/bacula/etc/bconsole.conf'
bc_bin = '/opt/comm-bacula/sbin/bconsole'
bc_cfg = '/opt/comm-bacula/etc/bconsole.conf'

# Define the location of the local bsys_report.pl
# -----------------------------------------------
local_script_name = 'bsys_report.pl'
local_script_dir = '/opt/comm-bacula/include/scripts'

# Where to upload the script on the remote servers?
# -------------------------------------------------
remote_tmp_dir ='/opt/bacula/working'

# --------------------------------------------------
# Nothing should need to be modified below this line
# --------------------------------------------------

# TODO: Maybe we add an option to download the latest bsys report generator script
# --------------------------------------------------------------------------------
# https://www.baculasystems.com/ml/bsys_report/bsys_report.tar.gz


# Define some functions
# ---------------------
def get_storages():
    'Get the Storage/Autochangers defined in the Director.'
    status = subprocess.run('echo -e ".storage\nquit\n" | ' + bc_bin + ' -c ' + bc_cfg, shell=True, capture_output=True, text=True)
    if re.match('(^.*(ERROR|invalid| Bad ).*|^Connecting to Director [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{4,5}$)', status.stdout, flags=re.DOTALL):
        print('Problem in get_storages()...')
        print('Reply from bconsole: \n====================================================\n' \
            + status.stdout + '====================================================')
        return False
    else:
        return re.sub('^.*storage\n(.*)(You have messages.)?\n.*quit.*', '\\1', status.stdout, flags=re.DOTALL).split()

def is_ip_address(address):
    'Given a string, determine if it is a valid IP address'
    try:
        ip_address(address)
        return True
    except ValueError:
        return False

def resolve(address):
    'Given a string, determine if it is resolvable to an IP address'
    try:
        data = socket.gethostbyname_ex(address)
        return data[2][0]
    except Exception:
        return False

# ------------
# Begin script
# ------------
import os
import re
import sys
import docopt
import socket
import tempfile
import subprocess
from datetime import datetime
from fabric import Connection
from ipaddress import ip_address, IPv4Address

print('\n- Script starting...')
now = datetime.now().strftime('%Y%m%d%H%M%S')
tar_filename = now + '.tgz'
# tar_filename = get_dir_name() + '_' + now + '.tgz'
remote_script_name = remote_tmp_dir + '/' + local_script_name
local_tmp_dir = tempfile.mkdtemp(dir='/tmp', prefix='all_bsys_reports-')
print('- Getting list of Storage/Autochanger resources from the Director.')
try:
    print('  - Found the following Storage/Autochanger resources: ' + ", ".join(get_storages()))
except:
    print('  - Problem occurred while getting Storage/Autochanger resources from the Director!')
    print('    - Exiting!')
    sys.exit(1)

# Create a dictionary of Storage resources defined in the Director
# ----------------------------------------------------------------
storage_dict = {}
print('  - Determining IP address for each Storage resource and creating unique host list.')
for st in get_storages():
    status = subprocess.run('echo -e "show storage=' + st + '\nquit\n" | ' \
           + bc_bin + ' -c ' + bc_cfg, shell=True, capture_output=True, text=True)
    address = re.sub('^.*Autochanger:.*address=(.+?) .*', '\\1', status.stdout, flags=re.DOTALL)
    print('\n  - Storage: ' + st + ', Address: ' + address)

    # Now determine if address is FQDN/host or IP address.
    # If address is FQDN/host, perform a DNS lookup to get
    # the IP and then replace address with IP obtained
    # ----------------------------------------------------
    if is_ip_address(address):
        ip = address
        print('      ' + address + ' is an IP address')
    else:
        print('      ' + address + ' is not an IP address. Attempting to resolve...')
        ip = resolve(address)
        if ip == False:
            print('      Oops, cannot resolve FQDN/host' + address)
        else:
            print('      FQDN/host ' + address + ' = ' + ip)

    # Now add name and IP to the storage_dict dictionary
    # but only if the IP address does not exist in values()
    # -----------------------------------------------------
    # for testing results output:
    # if ip != '10.1.1.4' and ip != '127.0.0.1' and ip not in storage_dict.values():
    if ip not in storage_dict.values():
        print('      Adding Storage "' + st + '" (' + ip + ') to gather bsys report from.')
        storage_dict[st] = ip
    else:
        print('      IP address for Storage "' + st + '" (' + ip + ') already in list. Skipping...')

print('\n- Will attempt to retrieve report' + ('' if len(storage_dict) == 1 else 's') \
    + ' from server' + ('' if len(storage_dict) == 1 else 's') \
    + ' with IP address' + ('' if len(storage_dict) == 1 else 'es') \
    + ': ' + ", ".join(storage_dict.values()) + '\n')

# Loop through the unique hosts (IP addresses) identifed
# ------------------------------------------------------
for host in storage_dict.values():
    print('  - Working on host: ' + host)
    c = Connection(host=host, user=user)

    # Upload the local bsys report script to the remote host
    # ------------------------------------------------------
    print('    - Uploading ' + local_script_dir + '/' + local_script_name + ' to ' + host + ':' + remote_tmp_dir)
    try:
        result = c.put(local_script_dir + '/' + local_script_name, remote=remote_tmp_dir)
    except:
        print('      - Problem uploading ' + local_script_dir + '/' + local_script_name + ' to ' + remote_tmp_dir)
        print('        - Skipping this host "' + st + '"!\n')
        continue
    print('      - Done')

    # Run the uploaded bsys report generator script and
    # capture the output to get the name of the report file
    # -----------------------------------------------------
    print('    - Running ' + host + ':' + remote_script_name + ' -o ' + remote_tmp_dir)
    try:
        result = c.run(remote_script_name + ' -o ' + remote_tmp_dir, hide=True)
    except:
        print('      - Problem encountered while trying to run remote script ' + host + ':' + remote_script_name)
        print('        - Skipping this host "' + st + '"!\n')
        continue
    print('      - Done')

    # Strip the comma off of the name that
    # was captured when the script was run
    # ------------------------------------
    remote_dl_file = result.stdout.split()[3].replace(',', '')

    # Create a filename for the downloaded bsys report
    # that is pre-pended with the host's IP address
    # ------------------------------------------------
    local_dl_file = local_tmp_dir + '/' + os.path.basename(remote_dl_file)

    # Now download the report
    # -----------------------
    print('    - Retrieving report ' + host + ':' +remote_dl_file + '\n      to local directory: ' + local_tmp_dir)
    try:
        result = c.get(remote_dl_file, local=local_dl_file)
    except:
        print('      - Problem encountered while trying to download remote bsys report ' + host + ':' + remote_dl_file + '\n      as: ' + local_dl_file)
        print('        - Skipping this host "' + st + '"!\n')
        continue
    print('      - Done\n')

# Create a tarball of all the downloaded bsys reports.
# Skip tarring if there is only one file, and report
# the results.
# ----------------------------------------------------
if len(storage_dict) <= 1:
    if len(storage_dict) == 0:
        print('- No bsys reports retreived.')
    elif len(storage_dict) == 1:
        print('- Only one bsys report retreived. Not creating tarball of one file.')
else:
    tar_err = False
    print('- Creating tarball of all bsys reports.')
    try:
        result = subprocess.run('cd ' + local_tmp_dir + '; tar -cvzf ' + tar_filename + ' *.gz', shell=True, capture_output=True, text=True)
    except:
        tar_err = True
        print('  - Problem encountered while trying to tar bsys reports.')
        print('  - Please check the local directory ' + local_tmp_dir)
    if tar_err == False:
        print('  - Done\n')
        if len(storage_dict) >= 1:
            print('- ' + ('All ' if len(storage_dict) > 1 else 'The ') + 'bsys report' \
                + ('s' if len(storage_dict) > 1 else '') + (' is' if len(storage_dict) == 1 else ' are') \
                + ' available in directory: ' + local_tmp_dir)
        print('- Archive (tgz) of all reports available as: ' + local_tmp_dir + '/' + tar_filename)
print('- Script complete.\n')


