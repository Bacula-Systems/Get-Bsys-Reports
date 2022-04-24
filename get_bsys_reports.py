#!/usr/bin/python3
# ------------------------------------------------------------------------
#  Bacula® - The Network Backup Solution

#  Copyright (C) 2000-2022 Bacula Systems SA All rights reserved.
#
#  The main author of Bacula is Kern Sibbald, with contributions from many
#  others, a complete list can be found in the file AUTHORS.
#
#  Licensees holding a valid Bacula Systems SA license may use this file and
#  others of this release in accordance with the proprietary license agreement
#  provided in the LICENSE file.  Redistribution of any part of this release is
#  not permitted.
#
#  Bacula® is a registered trademark of Kern Sibbald.
#
#  get_bsys_reports.py - Script to automatically collect bsys reports from
#  Director and all (or specific) Storage/Autochanger resources in Director's
#  configuration.
#
#  Written by Bill Arlofski, April 2022
# ------------------------------------------------------------------------
"""
--------------------------------
20220422 - waa - Initial release
--------------------------------
------------
INSTRUCTIONS
------------

- Please read ALL of these instructions before attempting to run this script.
  There are a lot of moving parts, and there are a lot of things (external to
  this script) that need to be working before using this script.

- The idea and workflow of this script is as follows:

  Given a command line option of '--ALL', this script will attempt to collect
  bsys reports from the Director server and all the Storage/Autochanger
  resources defined in the Director's configuration.

  You will first be asked to enter the ticket mask that these bsys reports are
  for (ie: TIA-91987-337), or your company name so that we know what ticket
  these reports are for.

  For the Director and each Storage/Autochanger resource found in the
  Director's configuration, this script will then get the "Address=" and
  determine if it is an IP address or not. If it is a host or FQDN, the script
  will attempt to resolve it to an IP address. If the DNS lookup fails to
  resolve the host/FQDN to an IP address it will flag an error and move on to
  the next host, skipping this one.

  Given names of Storage/Autochanger(s) on the command line, separated by
  spaces, the script will get the list of Storage/Autochanger resources from the
  Director, and then validate that each one that was provided on the command
  line is in the Director's configuration. If any are not, the script will
  print an error messages and exit.

  Once there is a valid list of Storage/Autochangers, the same process of
  getting an IP address for each one provided is performed.

  This list is created in such a way that there are no duplicate IP addresses
  so that only one report is gathered from each system.

  Once we have the list of unique IP addresses, the script will iterate
  through the list, upload the bsys_report.pl script file to the host, run the
  script, grab the unique name of the report tgz file that will be
  created, and when the script is finished, download the resulting report
  file from the host into a local temporary directory.

  When all reports are downloaded, if there are more than one, they will be
  tarred into one file that can be sent to Support.

  -----------------------------------------------------------------------------

- Now for the interesting REQUIRED things to be in place before this script
  can be successfully run:

  - This script REQUIRES Python >= 3.9 to run.
  - There are several Python modules that you will need to have installed on
    your system for this script to run. (see below)
  - You will need to download a current bsys report generator script from here:
    https://www.baculasystems.com/ml/bsys_report/bsys_report.tar.gz,
    untar/gunzip the perl `bsys_report.pl` script file, and set it executable.
  - Edit the `local_script_name` and `local_script_dir` variables in this script
    accordingly.
  - You MUST have already created a public/private ssh key pair on the host that
    will be running this script.
  - The public key must already be on each server that the script might need
    to retrieve a bsys report from.
  - The public key should be added to the ~/.ssh/authorized_keys file on the
    server of the user that the script will be connecting as (default `root`).
  - You must be running `ssh-agent` on the host that will run this script, and
    your private key MUST have already been added to it.
  - If you will be using a user other than `root` to connect to the remote
    hosts, there is the ability to use sudo to actually run the script. To do
    this, the `use_sudo` and `sudo_user` variables must be set properly.
  - Additionally, to use sudo, the user on each remote host must be allowed to
    run any command without being prompted for a password.
  - The script does not need to be run on the Director! If it is run on a 
    different host than the Director, then you must have bconsole installed on
    the host that will run the script, and a properly configured bconsole.conf
    configuration file that allows bconsole to communicate with the Director.
  - This script only uses the `.storage` and `show storage=xxxx` bconsole
    commands, so you may consider using a non-privileged Console configured in
    the Director to limit access.

  - REQUIRE MODULES:

    Before running this script, you will need to install several modules via pip:

    # sudo pip3 install docopt
    # sudo pip3 install fabric
    # sudo pip3 install termcolor

"""

# -----------------------------------------------------
# SET SOME VARIABLES SPECIFIC TO THE LOCAL ENVIRONMENT:
# -----------------------------------------------------
# Define the ssh user to use when connecting to remote systems
# ------------------------------------------------------------
ssh_user = 'root'

# Should sudo be used to run commands on remote servers?
# ------------------------------------------------------
use_sudo = 'no'
sudo_user = ''

# Define the bconsole program and config file locations
# -----------------------------------------------------
bc_bin = '/opt/bacula/bin/bconsole'
bc_cfg = '/opt/bacula/etc/bconsole.conf'

# Define the location of the local bsys_report.pl
# -----------------------------------------------
local_script_name = 'bsys_report.pl'
local_script_dir = './'

# Where to upload the script on the remote servers
# ------------------------------------------------
local_tmp_root_dir = '/tmp'  # This may be set to a more permanent location to keep history of reports
remote_tmp_dir = '/tmp'      # Must be writeable by the ssh_user on the remote hosts

# --------------------------------------------------
# Nothing should need to be modified below this line
# --------------------------------------------------

# TODO: Maybe we add an option to download the latest bsys report generator
# script https://www.baculasystems.com/ml/bsys_report/bsys_report.tar.gz
# -------------------------------------------------------------------------

# Define some functions
# ---------------------
def get_dir_info():
    'Get Director name and address'
    status = subprocess.run('echo -e "quit\n" | ' + bc_bin + ' -c ' + bc_cfg, shell=True, capture_output=True, text=True)
    name  = re.sub('^.* (.+?) Version:.*', '\\1', status.stdout, flags=re.DOTALL)
    address = re.sub('^Connecting to Director (.+?):.*', '\\1', status.stdout, flags=re.DOTALL)
    return name, address

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
    status = subprocess.run('echo -e "show storage=' + st + '\nquit\n" | ' + bc_bin + ' -c ' + bc_cfg, shell=True, capture_output=True, text=True)
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

def get_ip_address(address, type = None):
    'Give an address string, check if it is an IP, if not resolve it, add Director IP to host_dic'
    # Depending on type provided, (dir or st), print different messages and return different things
    # This is really ugly, but it prevents duplicate code for similar tasks for Director and Storages
    # -----------------------------------------------------------------------------------------------
    global errors
    if is_ip_address(address):
        print('      - ' + address + ' is an IP address')
        if type == 'dir':
            print('        - Adding Director\'s IP address ' + address + ' to list of hosts to retrieve report from.')
            host_dict['Director'] = address
        return address
    else:
        print('      - ' + address + ' is not an IP address. Attempting to resolve...')
        ip = resolve(address)
        if ip == False:
            errors += 1
            print(colored('      - Oops, cannot resolve FQDN/host ', 'red') + colored('"' + address + '"', 'red'))
            if type == 'dir':
                print(colored('        - Will not attempt to retrieve report from Director', 'red') + colored('"' + dir_name + '"', 'red'))
                return None
            else:
                print(colored('          - Removing ', 'red') + colored('"' + st + '"', 'red') + colored(' from host list', 'red'))
                storage_lst.remove(st)
                return 'removed'
        else:
            print('        - FQDN/host ' + address + ' = ' + ip)
            if type == 'dir':
                print('        - Adding Director\'s IP address ' + ip + ' to list of hosts to retrieve report from.')
                host_dict['Director'] = ip
        return ip

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
from termcolor import colored
from fabric import Connection
from ipaddress import ip_address, IPv4Address

# Set some variables
# ------------------
progname='Get Bsys Reports'
version = '1.00'
reldate = 'April 24, 2022'

# Define the docopt string
# ------------------------
doc_opt_str = """
Usage:
    get_bsys_reports.py (--ALL | SD...) [-m <mask>]
    get_bsys_reports.py -h | --help
    get_bsys_reports.py -v | --version

Options:
    --ALL              Get reports from the (local) DIR and all Storage Resources defined in Director configuration
    SD...              Get reports from specific Storage resources (ie: get_bsys_reports.py SD_01 SD_02 SD_03)
    -m, --mask <mask>  Ticket mask ID or company name. The tar file of bsys reports will have this prepended to it

    -h, --help         Print this help message
    -v, --version      Print the script name and version

"""

# Assign docopt doc string variable
# ---------------------------------
args = docopt(doc_opt_str, version='\n' \
+ progname + ' - v' + version \
+ '\n' + reldate + '\n' \
+ 'Written by: Bill Arlofski\n' \
+ 'Copyright® Bacula Systems, SA 2022\n')

# Print startup message and create some global variables
# ------------------------------------------------------
print(colored('\n- Script starting...', 'green', attrs=['bold']))
now = datetime.now().strftime('%Y%m%d%H%M%S')
remote_script_name = remote_tmp_dir + '/' + now + '_' + local_script_name
local_tmp_dir = tempfile.mkdtemp(dir=local_tmp_root_dir, prefix='all_bsys_reports-')
errors = 0

# Get the ticket mask or company name to prepend to the .tar file name
# --------------------------------------------------------------------
if args['--mask'] != None:
    mask = args['--mask']
else:
    while True:
        mask = input('  - Enter the ticket mask (preferred) or your company name (no spaces): ')
        if ' ' in mask or len(mask) == 0:
            print('    - Input must not contain spaces, and must not be empty. Try again.')
        else:
            break
tar_filename = mask + '_' + now + '.tar'

# Get all the Storages/Autochangers defined in the Director config
# ----------------------------------------------------------------
storage_lst = []
try:
    print(colored('  - Getting list of Storage/Autochanger resources from the Director.', 'white', attrs=['bold']))
    all_storage_lst = get_storages()
    print('    - Found the following Storage/Autochanger resources: ' + colored(", ".join(all_storage_lst), 'yellow'))
except:
    print(colored('- Problem occurred while getting Storage/Autochanger resources from the Director!', 'red'))
    print(colored('  - Exiting!\n', 'red'))
    sys.exit(1)

if args['--ALL']:
    print(colored('\n  - Option \'--All\' provided on command line. Will attempt to get reports from Director and all Storages.', 'white', attrs=['bold']))
    storage_lst = all_storage_lst
else:
    print(colored('\n  - The following Storage/Autochanger resource' \
          + ('s were' if len(args['SD']) > 1 else ' was') \
          + ' provided on the command line: ', 'white', attrs=['bold']) \
          + colored(", ".join(args['SD']), 'yellow'))
    print('    - Checking validity of given Storage/Autochanger resources.')
    for st in args['SD']:
        if st in all_storage_lst:
            print(colored('      - Storage ' + st + ' is valid.', 'green'))
            storage_lst.append(st)
        else:
            print(colored('      - Storage ' + st + ' is not a valid Storage/Autochanger.', 'red'))
            print(colored('        - Exiting.\n', 'red'))
            sys.exit(1)

# Create a dictionary of Storage resources defined in the Director
# ----------------------------------------------------------------
host_dict = {}
print(colored('\n  - Determining IP address for ' + ('Director and ' if args['--ALL'] else '') \
      + 'Storage resource' + ('s' if len(storage_lst) > 1 else '') \
      + ' and creating unique host list.', 'white', attrs=['bold']))

if args['--ALL']:
    dir_name, dir_address = get_dir_info()
    print(colored('    - Director: ', 'green') + colored(dir_name, 'yellow') + ', ' \
          + colored('Address: ', 'green') + colored(dir_address, 'yellow'))
    get_ip_address(dir_address, 'dir')

for st in storage_lst:
    address = get_storage_address(st)
    print(colored('    - Storage: ', 'green') + colored(st, 'yellow') + ', ' \
          + colored('Address: ', 'green') + colored(address, 'yellow'))

    # Now determine if address is FQDN/host or IP address.
    # If address is FQDN/host, perform a DNS lookup to get
    # the IP and then replace address with IP obtained
    # ----------------------------------------------------
    ip = get_ip_address(address, 'st')
    if ip == 'removed':
        continue

    # Now add name and IP to the host_dict dictionary
    # but only if the IP address does not exist in values
    # ---------------------------------------------------
    if ip not in host_dict.values():
        print('        - Adding Storage "' + st + '" (' + ip + ') to gather bsys report from.')
        host_dict[st] = ip
    else:
        print('      - IP address for ' + ('Storage ' if not st == 'DIR' else 'local ') + '"' \
               + st + '" (' + ip + ') already in list. Skipping...')

# Now get the reports from each qualified host
# --------------------------------------------
if len(host_dict) == 0:
    print(colored('\n  - There are no valid Storages/Autochangers to gather reports from!', 'red'))
else:
    print(colored('\n  - Attempting to retrieve report' + ('' if len(host_dict) == 1 else 's') \
        + ' from server' + ('' if len(host_dict) == 1 else 's') \
        + ' with IP address' + ('' if len(host_dict) == 1 else 'es') \
        + ': ', 'white', attrs=['bold'])+ colored(", ".join(host_dict.values()), 'yellow'))

    # Iterate through the unique hosts (IP addresses) identifed and then
    # upload the bsys_report.pl script, run it, and download the report
    # ------------------------------------------------------------------
    reports = 0
    for host in host_dict.values():
        print(colored('    - Working on host: ', 'green') + colored(host, 'yellow'))
        # I am surely doing this wrong for sudo use, but in limited testing,
        # it worked. I think I need to c.close() and re-open for the c.run()
        # This needs to be inspected further.
        # ------------------------------------------------------------------
        c = Connection(host = host, user = ssh_user)
        # c.close()

        # Upload the local bsys report generator script to the remote host with
        # a timestamped filename to prevent overwrites or permission issues
        # ---------------------------------------------------------------------
        print('      - Uploading ' + local_script_dir + '/' + local_script_name + ' to ' + host + ':' + remote_tmp_dir)
        try:
            result = c.put(local_script_dir + '/' + local_script_name, remote=remote_script_name)
        except:
            errors += 1
            print(colored('        - Problem uploading ' + local_script_dir + '/' \
                  + local_script_name + ' to ' + remote_tmp_dir, 'red'))
            print(colored('          - Skipping this host "' + host + '"!\n', 'red'))
            continue
        print(colored('        - Done', 'green'))

        # Run the uploaded bsys report generator script and
        # capture the output to get the name of the report file
        # -----------------------------------------------------
        print('      - Running ' + ('(via sudo) ' if use_sudo == 'yes' else '') \
        + ('as user ' + sudo_user + ' ' if sudo_user != '' else '') \
        + host + ':' + remote_script_name + ' -o ' + remote_tmp_dir)
        try:
            if use_sudo == 'yes':
                if sudo_user != '':
                    result = c.sudo(remote_script_name + ' -o ' + remote_tmp_dir, user=sudo_user, hide=True)
                else:
                    result = c.sudo(remote_script_name + ' -o ' + remote_tmp_dir, hide=True)
            else:
                result = c.run(remote_script_name + ' -o ' + remote_tmp_dir, hide=True)
        except:
            errors += 1
            print(colored('        - Problem encountered while trying to run remote script ' \
                  + host + ':' + remote_script_name, 'red'))
            print(colored('          - Skipping this host "' + host + '"!\n', 'red'))
            continue
        print(colored('        - Done', 'green'))

        # Strip the comma off of the name that
        # was captured when the script was run
        # ------------------------------------
        remote_dl_file = result.stdout.split()[3].replace(',', '')

        # Create a filename for the downloaded bsys report
        # that is pre-pended with the host's IP address
        # Prepend the local filename(s) of the downloaded
        # bsys report(s) with DIR or SD, depending on which
        # type it is. Even if the Director server has a
        # Storage defined on it, if '--ALL' was used on the
        # command line, the Director IP will always be first
        # in the dictionary because we add it first.
        # --------------------------------------------------
        # Use a dictionary comprehension to invert the keys and values
        # of the 'host_dict' dictionary so we can get the name of the
        # Storage (or 'Director' in the case of a Director IP), from
        # the IP address as the key.
        # https://peps.python.org/pep-0274/
        # https://stackoverflow.com/a/18043402
        # ------------------------------------------------------------
        res = {v: k for k, v in host_dict.items()}
        if res[host] == 'Director':
            local_dl_file = local_tmp_dir + '/' + 'DIR-' + os.path.basename(remote_dl_file)
        else:
            local_dl_file = local_tmp_dir + '/' + 'SD-' + os.path.basename(remote_dl_file)

        # Now download the report
        # -----------------------
        print('      - Retrieving report ' + host + ':' + remote_dl_file)
        try:
            result = c.get(remote_dl_file, local=local_dl_file)
            reports += 1
        except:
            errors += 1
            print(colored('        - Problem encountered while trying to download remote bsys report ' \
                  + host + ':' + remote_dl_file + '\n      as: ' + local_dl_file, 'red'))
            print(colored('          - Skipping this host "' + host + '"!\n', 'red'))
            continue
        print(colored('        - Done', 'green'))

# Create a tarball of all the downloaded bsys reports.
# Skip tarring if there is only one file, and report
# the results.
# ----------------------------------------------------
if len(host_dict) <= 1:
    if len(host_dict) == 0 or reports == 0:
        print(colored('  - No bsys reports retrieved.', 'red'))
    elif len(host_dict) == 1:
        print(colored('  - Only one bsys report retrieved.', 'white', attrs=['bold']))
        print('    - Not creating a tarball of one file.')
        print(colored('  - The one bsys report is here: ', 'white', attrs=['bold']) + colored(local_dl_file, 'yellow'))
else:
    tar_err = False
    print(colored('\n  - Creating tarball of all bsys reports.', 'white', attrs=['bold']))
    try:
        result = subprocess.run('cd ' + local_tmp_dir + '; tar -cf ' + tar_filename + ' *.gz', shell=True, capture_output=True, text=True)
    except:
        errors += 1
        tar_err = True
        print(colored('    - Problem encountered while trying to tar bsys reports.', 'red'))
        print(colored('    - Please check the local directory: ', 'red') + local_tmp_dir)
    if tar_err == False:
        print(colored('    - Done\n', 'green'))
        if len(host_dict) >= 1:
            print(colored('  - ' + ('All ' if len(host_dict) > 1 else 'The ') + 'bsys report' \
                  + ('s' if len(host_dict) > 1 else '') + (' is' if len(host_dict) == 1 else ' are') \
                  + ' available in directory: ', 'white', attrs=['bold']) + colored(local_tmp_dir, 'yellow'))
        print(colored('  - Archive (tar) of all reports available as: ', 'white', attrs=['bold']) \
              + colored(local_tmp_dir + '/' + tar_filename, 'yellow'))
if errors > 0:
    print(colored('  - (' + str(errors) + ') Error' + ('s were' if errors > 1 else ' was') \
          + ' detected during script run. Please check the script output above!', 'red', attrs=['bold']))
print(colored('- Script complete.\n', 'green', attrs=['bold']))
