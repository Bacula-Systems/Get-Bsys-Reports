#!/usr/bin/python3

# 20220406 - waa - Initial notes and ideas
# ----------------------------------------
#
# - Command line options... --all (DIR, and all SDs), --dir (Just the DIR), --sds (All SDs), SD,SD,SD (specific SDs)
#   NOTE: ** This ended up being just --ALL or a space separated list of Storage/Autochanger resource names **
# - Get Dir name from `s dir`   - No need, decided to ask for ticket mask instead
#   - the tgz file will now be named 'ticketmask_yyyymmddhhmmss.tgz' or 'CompanyName_yyyymmddhhmmss.tgz'
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
# TODO: Maybe we add an option to download the latest bsys report generator script
# https://www.baculasystems.com/ml/bsys_report/bsys_report.tar.gz
#
# --------------------------------------------------------------------------------

# Need to install several modules via pip:
#
# sudo pip3 install fabric
# sudo pip3 install docopt
# sudo pip3 install termcolor

# SET SOME VARIABLES SPECIFIC TO THE LOCAL ENVIRONMENT:
# -----------------------------------------------------

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

# Where to upload the script on the remote servers
# ------------------------------------------------
remote_tmp_dir ='/opt/bacula/working'

# --------------------------------------------------
# Nothing should need to be modified below this line
# --------------------------------------------------

# Define some functions
# ---------------------
def get_storages():
    'Get the Storage/Autochangers defined in the Director.'
    status = subprocess.run('echo -e ".storage\nquit\n" | ' + bc_bin + ' -c ' + bc_cfg, shell=True, capture_output=True, text=True)
    if re.match('(^.*(ERROR|invalid| Bad ).*|^Connecting to Director [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{4,5}$)', status.stdout, flags=re.DOTALL):
        print(colored('    - Problem in get_storages()...', 'red', attrs=['bold']))
        print(colored('- Reply from bconsole:', 'red'))
        print('==========================================================\n' \
            + status.stdout + '==========================================================')
        return False
    else:
        # I could not get this regex to work for 0 or 1 of 'You have messages.\n'... grrrrr
        # return re.sub('.*storage\n(.*)(You have messages.\n)?quit.*', '\\1', status.stdout, flags=re.DOTALL)
        # So I reverted to a .replace() on the status.stdout from subprocess.run first, then the re.sub
        yhmstripped = status.stdout.replace('You have messages.\n', '')
        return re.sub('.*storage\n(.*)quit.*', '\\1', yhmstripped, flags=re.DOTALL).split()

def get_storage_address(st):
    'Given a Director Storage/Autochanger name, return the IP address'
    status = subprocess.run('echo -e "show storage=' + st + '\nquit\n" | ' \
           + bc_bin + ' -c ' + bc_cfg, shell=True, capture_output=True, text=True)
    return re.sub('^.*[Storage|Autochanger]:.*address=(.+?) .*', '\\1', status.stdout, flags=re.DOTALL)

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

# Import modules and methods
# --------------------------
import os
import re
import sys
import socket
import tempfile
import subprocess
from docopt import docopt
from datetime import datetime
from fabric import Connection
from termcolor import colored
from ipaddress import ip_address, IPv4Address

# Set some variables
# ------------------
progname='Get Bsys Reports'
version = '1.00'
reldate = 'April 18, 2022'

# Define the docopt string
# ------------------------
doc_opt_str = """
Usage:
    get_bsys_reports.py (--ALL | <SD>...)
    get_bsys_reports.py -h | --help
    get_bsys_reports.py -v | --version

Options:
    --ALL          Get reports from the (local) DIR and all Storage Resources defined in Director configuration
    <SD>...        Get reports from specific Storage resources (ie: get_bsys_reports.py SD_01 SD_02 SD_03)

    -h, --help     Print this help message
    -v, --version  Print the script name and version

"""

# ----------------
# Start the script
# ----------------
# Assign docopt doc string variable
# ---------------------------------
args = docopt(doc_opt_str, version='\n' + progname + ' - v' + version + '\n' + reldate + '\n')
print(colored('\n- Script starting...', 'green', attrs=['bold']))
now = datetime.now().strftime('%Y%m%d%H%M%S')
remote_script_name = remote_tmp_dir + '/' + local_script_name
local_tmp_dir = tempfile.mkdtemp(dir='/tmp', prefix='all_bsys_reports-')

# Get the ticket mask or company name to name the .tgz file
# ---------------------------------------------------------
while True:
    mask = input('  - Enter the ticket mask (preferred) or your company name (no spaces): ')
    if ' ' in mask or len(mask) == 0:
        print('    - Input must not contain spaces, and must not be empty. Try again.')
    else:
        tar_filename = mask + '_' + now + '.tgz'
        break

# Get all the Storages/Autochangers defined in the Director config
# ----------------------------------------------------------------
storage_lst = []
try:
    print('  - Getting list of Storage/Autochanger resources from the Director.')
    all_storage_lst = get_storages()
    print('    - Found the following Storage/Autochanger resources: ' + colored(", ".join(all_storage_lst), 'yellow'))
except:
    print(colored('- Problem occurred while getting Storage/Autochanger resources from the Director!', 'red'))
    print(colored('  - Exiting!\n', 'red'))
    sys.exit(1)

if args['--ALL']:
    print('  - Option \'--All\' provided on command line. Will attempt to get reports from local DIR and all SDs')
    all_storage_lst.append('DIR')
    storage_lst = all_storage_lst
else:
    print('  - The following Storage/Autochanger resources were provided on the command line: ' + colored(", ".join(args['<SD>']), 'yellow'))
    print('    - Checking validity of given Storage/Atuochanger resources.')
    for st in args['<SD>']:
        if st in all_storage_lst:
            print(colored('      - Storage ' + st + ' is valid.', 'green'))
            storage_lst.append(st)
        else:
            print(colored('      - Storage ' + st + ' is not a valid Storage/Autochanger.', 'red'))
            print(colored('        - Exiting.\n', 'red'))
            sys.exit(1)

# Create a dictionary of Storage resources defined in the Director
# ----------------------------------------------------------------
storage_dict = {}
print(colored('\n    - Determining IP address for each Storage resource and creating unique host list.', 'white', attrs=['bold']))
for st in storage_lst:
    if st == 'DIR':
        address = '127.0.0.1'
    else:
        address = get_storage_address(st)
    print(colored('      - Storage: ', 'green') + colored(st, 'yellow') + ', ' + colored('Address: ', 'green') + colored(address, 'yellow'))

    # Now determine if address is FQDN/host or IP address.
    # If address is FQDN/host, perform a DNS lookup to get
    # the IP and then replace address with IP obtained
    # ----------------------------------------------------
    if is_ip_address(address):
        ip = address
        print('        - ' + address + ' is an IP address')
    else:
        print('        - ' + address + ' is not an IP address. Attempting to resolve...')
        ip = resolve(address)
        if ip == False:
            print(colored('          - Oops, cannot resolve FQDN/host ', 'red') + address)
            continue
        else:
            print('          - FQDN/host ' + address + ' = ' + ip)

    # Now add name and IP to the storage_dict dictionary
    # but only if the IP address does not exist in values
    # ---------------------------------------------------
    if ip not in storage_dict.values():
        print('        - Adding Storage "' + st + '" (' + ip + ') to gather bsys report from.')
        storage_dict[st] = ip
    else:
        print('        - IP address for ' + ('Storage ' if not st == 'DIR' else 'local ') + '"' + st + '" (' + ip + ') already in list. Skipping...')

# Now get the reports from each qualified host
# --------------------------------------------
if len(storage_dict) == 0:
    print(colored('\n  - There are no valid Storages/Autochangers to gather reports from!', 'red'))
else:
    print(colored('\n  - Will attempt to retrieve report' + ('' if len(storage_dict) == 1 else 's') \
        + ' from server' + ('' if len(storage_dict) == 1 else 's') \
        + ' with IP address' + ('' if len(storage_dict) == 1 else 'es') \
        + ': ', 'white', attrs=['bold'])+ colored(", ".join(storage_dict.values()), 'yellow'))

    # Loop through the unique hosts (IP addresses) identifed and then
    # upload the bsys_report.pl script, run it, and download the report
    # -----------------------------------------------------------------
    reports = 0
    for host in storage_dict.values():
        print(colored('    - Working on host: ', 'green') + colored(host, 'yellow'))
        c = Connection(host=host, user=user)

        # Upload the local bsys report script to the remote host
        # ------------------------------------------------------
        print('      - Uploading ' + local_script_dir + '/' + local_script_name + ' to ' + host + ':' + remote_tmp_dir)
        try:
            result = c.put(local_script_dir + '/' + local_script_name, remote=remote_tmp_dir)
        except:
            print(colored('        - Problem uploading ' + local_script_dir + '/' + local_script_name + ' to ' + remote_tmp_dir, 'red'))
            print(colored('          - Skipping this host "' + host + '"!\n', 'red'))
            continue
        print(colored('        - Done', 'green'))

        # Run the uploaded bsys report generator script and
        # capture the output to get the name of the report file
        # -----------------------------------------------------
        print('      - Running ' + host + ':' + remote_script_name + ' -o ' + remote_tmp_dir)
        try:
            result = c.run(remote_script_name + ' -o ' + remote_tmp_dir, hide=True)
        except:
            print(colored('        - Problem encountered while trying to run remote script ' + host + ':' + remote_script_name, 'red'))
            print(colored('          - Skipping this host "' + host + '"!\n', 'red'))
            continue
        print(colored('        - Done', 'green'))

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
        print('      - Retrieving report ' + host + ':' + remote_dl_file)
        try:
            result = c.get(remote_dl_file, local=local_dl_file)
            reports += 1
        except:
            print(colored('        - Problem encountered while trying to download remote bsys report ' + host + ':' + remote_dl_file + '\n      as: ' + local_dl_file, 'red'))
            print(colored('          - Skipping this host "' + host + '"!\n', 'red'))
            continue
        print(colored('        - Done\n', 'green'))

# Create a tarball of all the downloaded bsys reports.
# Skip tarring if there is only one file, and report
# the results.
# ----------------------------------------------------
if len(storage_dict) <= 1:
    if len(storage_dict) == 0 or reports == 0:
        print(colored('  - No bsys reports retreived.', 'red'))
    elif len(storage_dict) == 1:
        print('  - Only one bsys report retreived. Not creating tarball of one file.')
        print('    - The one bsys report is located in ' + local_dl_file)
else:
    tar_err = False
    print(colored('  - Creating tarball of all bsys reports.', 'white', attrs=['bold']))
    try:
        result = subprocess.run('cd ' + local_tmp_dir + '; tar -cvzf ' + tar_filename + ' *.gz', shell=True, capture_output=True, text=True)
    except:
        tar_err = True
        print(colored('    - Problem encountered while trying to tar bsys reports.', 'red'))
        print(colored('    - Please check the local directory ', 'red') + local_tmp_dir)
    if tar_err == False:
        print(colored('    - Done\n', 'green'))
        if len(storage_dict) >= 1:
            print('  - ' + ('All ' if len(storage_dict) > 1 else 'The ') + 'bsys report' \
                + ('s' if len(storage_dict) > 1 else '') + (' is' if len(storage_dict) == 1 else ' are') \
                + ' available in directory: ' + local_tmp_dir)
        print('  - Archive (tgz) of all reports available as: ' + local_tmp_dir + '/' + tar_filename)
print(colored('- Script complete.\n', 'green', attrs=['bold']))


