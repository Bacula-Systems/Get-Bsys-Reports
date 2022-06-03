#!/usr/bin/python3
# -----------------------------------------------------------------------------
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
#  Initial version written by Bill Arlofski, April-May 2022
# -----------------------------------------------------------------------------

# Define the docopt string
# ------------------------
doc_opt_str = """
Usage:
    get_bsys_reports.py (--all | --dir | <st>... | --dir <st>...) [-c <bconfig>] [-g] [-m <mask>] [-p <pass>]
    get_bsys_reports.py -h | --help
    get_bsys_reports.py -v | --version

Options:
    --all                    Get reports from the Director and all Storage Resources defined in Director's configuration.
    --dir                    Get a report from the Director. --all implies --dir and these two are mutually exclusive.
    <st>...                  Get reports from one or more specific Storage resources (ie: get_bsys_reports.py ST1 ST2 ST3).
    -c, --bconfig <bconfig>  Specify the bconsole.conf file to use. (/opt/bacula/etc/bconsole.conf).
    -g, --get-bsys-report    Download current bsys report generator script from Bacula Systems' website.
    -m, --mask <mask>        Ticket mask ID or company name. The tar file of bsys reports will have this text prepended to it.
    -p, --pass <pass>        SSH private key passphrase, or ssh user passphrase

    -h, --help               Print this help message.
    -v, --version            Print the script name and version.

"""

"""
--------------------------------
20220422 - waa - Initial release
--------------------------------
------------
INSTRUCTIONS
------------

- Please read ALL of these instructions before attempting to run this
  script.  There are a lot of moving parts, and there are a lot of things
  (external to this script) that need to be working before using this
  script.

- The idea and workflow of this script is as follows:

    Given a command line option of '--all', this script will attempt to
    collect bsys reports from the Director server and all the
    Storage/Autochanger resources defined in the Director's configuration.

    You will first be asked to enter the ticket mask that these bsys
    reports are for (ie: TIA-91987-337), or your company name so that we
    know what ticket these reports are for. You may use -m <mask> to
    provide this on the command line to help automate collecting bsys
    reports from your servers.

    For the Director and each Storage/Autochanger resource found in the
    Director's configuration, this script will then get the "Address=" and
    determine if it is an IP address or not. If it is a hostname or FQDN,
    the script will attempt to resolve it to an IP address. If the DNS
    lookup fails to resolve the hostiname/FQDN to an IP address it will
    flag an error and move on to the next host, skipping this one.

    Given names of Storage/Autochanger(s) on the command line, separated by
    spaces, the script will get the list of Storage/Autochanger resources
    from the Director, and then validate that each one that was provided on
    the command line is in the Director's configuration. If any are not,
    the script will print an error message and exit.

    Once there is a valid list of Storage/Autochangers, the same process of
    getting an IP address for each one provided is performed.

    This host list is created in such a way that there are no duplicate IP
    addresses so that only one report is gathered from each system.

    Once we have the list of unique IP addresses, the script will iterate
    through the list, upload the bsys_report.pl script file to the host,
    run the script, grab the unique name of the report gzip file that will
    be created, and when the script is finished running, download the
    resulting report file from the host into a local temporary directory.

    When all reports are downloaded, if there is more than one, they will
    be tarred into one file that can be sent to the Bacula Systems Support
    Team.

  -----------------------------------------------------------------------------

- Now for the REQUIRED things to be in place before this script can be
  successfully run:

  - This script REQUIRES Python >= 3.6 to run.

  - There are several Python modules that you will need to have installed on
    your system for this script to run. (see below)

  - Edit the `local_script_dir` and `local_script_name` variables in this
    script accordingly.

  - If the system that this script will run on has Internet access, you can
    use the '-g' (--get-bsys-report) command line option and the script
    will automatically download the current bsys report generator script
    from the Bacula Systems website, untar it, set it executable, and move
    it to the 'local_script_dir' directory.

  - If the system that will run this script does not have Internet access,
    you will need to download a current bsys report generator script from
    here: https://www.baculasystems.com/ml/bsys_report/bsys_report.tar.gz,
    untar/gunzip the perl `bsys_report.pl` script file inside, set it
    executable, and copy it to the 'local_script_dir' directory.

  - If you do not want to put the ssh private key passphrase on the command
    line or in this script, then the following recommended steps must be
    taken first:

        - You must have already created a private/public ssh key pair on
          the host that will be running this script.

        - The public key must already be on each Director and SD server
          that the script might need to retrieve a bsys report from.

        - The public key should be added to the ~/.ssh/authorized_keys file
          the user on the remote servers that the script will be connecting
          as (default `root`). The best way to do this is with the
          `ssh-copy-id` utility.

        - If the private key has a passphrase, then you must be running
          `ssh-agent` on the host that will run this script, and your
          private key MUST have already been added to it. The keychain
          utility is a nice way to add your ssh private keys to ssh-agent
          on login.

  - The script does not need to be run on the Director! If it is run on a
    different host than the Director, then you must have bconsole installed
    on the host that will run the script, and a properly configured
    bconsole.conf configuration file(s) that allows bconsole to communicate
    with the Director(s).

  - In a multi-Director environment, you may create a bconsole.conf file
    for each Director, and then use the '-c' <bconfig> command line option
    to tell the script which configuration file to use, and hence which
    Director and Storages to retreive bsys reports from.

  - This script only uses the bconsole `.storage` and `show storage=xxxx`
    commands, so you may consider using a non-privileged Console configured in
    the Director to limit access to just these commands.

  - REQUIRED MODULES:

        Before running this script, you will need to install several
        modules via pip:

        # sudo pip3 install docopt
        # sudo pip3 install requests
        # sudo pip3 install termcolor

"""

# ----------------------------------------------------
# SET SOME VARIABLES SPECIFIC TO THE LOCAL ENVIRONMENT
# ----------------------------------------------------
# Define the ssh user to use when connecting to remote systems
# ------------------------------------------------------------
ssh_user = 'root'
ssh_priv_key_pass = ''  # It is NOT recommended to set this!
                        # See above about setting up ssh-agent
                        # or passphraseless ssh private key!

# Define the bconsole program and config file locations
# -----------------------------------------------------
bc_bin = '/opt/bacula/bin/bconsole'
bc_cfg = '/opt/bacula/etc/bconsole.conf'

# Define the location of the local bsys_report.pl
# -----------------------------------------------
local_script_dir = './'
local_script_name = 'bsys_report.pl'

# Where to upload the script on the remote servers
# ------------------------------------------------
remote_tmp_dir = '/tmp'      # Must be writeable by the ssh_user on the remote hosts
local_tmp_root_dir = '/tmp'  # This may be set to a more permanent location to keep a history of reports

# --------------------------------------------------
# Nothing should need to be modified below this line
# --------------------------------------------------

# Define some functions
# ---------------------
def dir_conn_error(status):
    print(status)
    print(colored('    - Error connecting to the Director', 'red'))
    print(colored('      - Exiting!\n', 'red'))
    sys.exit(1)

def get_dir_info():
    'Get Director name and address'
    cmd = f"echo -e 'quit\n' | {bc_bin} -c {bc_cfg}"
    status = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    # A try test does not catch errors, but
    # a status.returncode test works here
    # -------------------------------------
    if status.returncode != 0:
        dir_conn_error(status.stdout)
    else:
        name = re.sub('^.* (.+?) Version:.*', '\\1', status.stdout, flags=re.DOTALL)
        address = re.sub('^Connecting to Director (.+?):.*', '\\1', status.stdout, flags=re.DOTALL)
        return name, address

def get_storages():
    'Get the Storage/Autochangers defined in the Director.'
    print(colored('\n  - Getting list of all Storage/Autochanger resources from the Director.', 'white', attrs=['bold']))
    cmd = f"echo -e '.storage\nquit\n' | {bc_bin} -c {bc_cfg}"
    status = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    # A try test does not catch errors, but
    # a status.returncode test works here
    # -------------------------------------
    if status.returncode != 0:
        dir_conn_error(status.stdout)
    else:
        if re.match('(^.*(ERROR|invalid| Bad ).*|^Connecting to Director [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{4,5}$)', status.stdout, flags=re.DOTALL):
            print(colored('    - Problem in get_storages()...', 'red', attrs=['bold']))
            print(colored('- Reply from bconsole:', 'red'))
            print('==========================================================\n' \
                + status.stdout + '==========================================================')
            print(colored('- Problem occurred while getting Storage/Autochanger resources from the Director!', 'red'))
            print(colored('  - Exiting!\n', 'red'))
            sys.exit(1)
        else:
            # return re.sub('.*storage\n(.*)(You have messages.\n)?quit.*', '\\1', status.stdout, flags=re.DOTALL)
            # I could not get this regex to work for 0 or 1 of 'You have messages.\n'... grrrrr
            # So I reverted to a .replace() on the status.stdout from subprocess.run first, then the re.sub
            yhmstripped = status.stdout.replace('You have messages.\n', '')
            storages_split = re.sub('.*storage\n(.*)quit.*', '\\1', yhmstripped, flags=re.DOTALL).split()
            print('    - Found the following Storage/Autochanger resource' + ('s' if len(storages_split) > 1 else '') + ' configured in the Director: ' + colored(", ".join(storages_split), 'yellow'))
            return storages_split

def get_storage_address(st):
    'Given a Director Storage/Autochanger name, return the IP address'
    cmd = f"echo -e 'show storage={st}\nquit\n' | {bc_bin} -c {bc_cfg}"
    status = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    # A try test does not catch errors, but
    # a status.returncode test works here
    # -------------------------------------
    if status.returncode != 0:
        dir_conn_error(status.stdout)
    else:
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

def get_ip_address(address, type=None):
    'Given an address string, check if it is an IP, if not resolve it, add Director IP to host_dic'
    # Depending on type provided, (dir or st), print different messages and
    # return different things This is really ugly, and not very Pythonic, but
    # it prevents duplicate code for similar tasks for Director and Storages
    # -----------------------------------------------------------------------
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

def get_bsys_report():
    'Download the current bsys report generator script from Bacula Systems'
    dl_file = now + '_bsys_report.tar.gz'
    url = 'https://www.baculasystems.com/ml/bsys_report/bsys_report.tar.gz'
    print(colored('  - Option \'-g\' (--get-bsys-report) provided on command line. Downloading bsys_report.tar.gz', 'white', attrs=['bold']))
    try:
        response = requests.get(url)
        if response.ok:
            print('    - Successfully downloaded ' + url + ' to ' + local_tmp_root_dir +'/' + dl_file)
            open(local_tmp_root_dir +'/' + dl_file, 'wb').write(response.content)
    except:
        print(colored('    - Error downloading bsys report generator script! (' + url + ')', 'red'))
        print(colored('      - Exiting!\n', 'red'))
        sys.exit(1)

    # If everything OK, unpack the script and chmod +x it.
    # ----------------------------------------------------
    cmd = f"tar xvzf {local_tmp_root_dir}/{dl_file} -C {local_tmp_root_dir}"
    status = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if status.returncode == 0:
        print('      - Successfully untarred ' + local_tmp_root_dir + '/' + dl_file + ' to ' + local_tmp_root_dir)
    else:
        print(colored('      - Error untarring file!', 'red'))
        print(colored('      - Exiting!\n', 'red'))
        sys.exit(1)

    # Now we chmod +x the script
    # --------------------------
    cmd = f"chmod +x {local_tmp_root_dir}/bsys_report.pl"
    status = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if status.returncode == 0:
        print('      - Successfully chmod +x ' + local_tmp_root_dir + '/bsys_report.pl')
    else:
        print(colored('      - Error chmod +x bsys_report.pl file!', 'red'))
        print(colored('      - Exiting!\n', 'red'))
        sys.exit(1)

    # Now move the script
    # -------------------
    local_script_name = 'bsys_report.pl'
    cmd = f"mv {local_tmp_root_dir}/bsys_report.pl {local_script_dir}/{local_script_name}"
    status = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if status.returncode == 0:
        print('      - Successfully moved ' + local_tmp_root_dir + '/bsys_report.pl' + ' to ' + local_script_dir)
    else:
        print(colored('      - Error moving bsys_report.pl file!', 'red'))
        print(colored('      - Exiting!\n', 'red'))
        sys.exit(1)
    print('')
# ----------------
# End of functions
# ----------------

# Import modules and methods
# --------------------------
import os
import re
import sys
import socket
import tempfile
import requests
import subprocess
from docopt import docopt
from datetime import datetime
from termcolor import colored
from paramiko import SSHClient, ssh_exception, AutoAddPolicy
from ipaddress import ip_address, IPv4Address

# Set some variables
# ------------------
progname='Get Bsys Reports'
version = '1.12'
reldate = 'June 03, 2022'

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

# If the passphrase was entered on the command
# line, set the ssh_priv_key_pass variable
# --------------------------------------------
if args['--pass'] != None:
    ssh_priv_key_pass = args['--pass']

# Get the ticket mask or company name to prepend to the .tar file name
# --------------------------------------------------------------------
if args['--mask'] != None:
    mask = re.sub('\s+', '_', args['--mask'])
else:
    while True:
        mask = re.sub('\s+', '_', input(colored('  - Enter the ticket mask (preferred) or your company name: ', 'white', attrs=['bold'])))
        if len(mask) == 0:
            print('    - Input must not be empty. Try again.')
        else:
            break

# Check if we have a bconsole config specified on the command line
# Assign it if we do, otherwise use the default defined above
# ----------------------------------------------------------------
if args['--bconfig'] != None:
    bc_cfg = args['--bconfig']

# Do we get the current bsys report generator script
# --------------------------------------------------
if args['--get-bsys-report']:
    get_bsys_report()

# Get all the Storages/Autochangers defined in the Director config
# ----------------------------------------------------------------
storage_lst = []
if args['--all']:
    print(colored('  - Option \'--all\' provided on command line. Will attempt to get reports from Director and all Storages.', 'white', attrs=['bold']))
    all_storage_lst = get_storages()
elif args['--dir']:
    print(colored('  - Option \'--dir\' provided on command line. Will attempt to get report from the Director.\n', 'white', attrs=['bold']))

if len(args['<st>']) > 0:
    print(colored('  - The following Storage/Autochanger resource' \
          + ('s were' if len(args['<st>']) > 1 else ' was') \
          + ' provided on the command line: ', 'white', attrs=['bold']) \
          + colored(", ".join(args['<st>']), 'yellow'))
    print('    - Checking validity of provided Storage/Autochanger resource' + ('s' if len(args['<st>']) > 1 else '') + '.')
    all_storage_lst = get_storages()

if args['--all'] or len(args['<st>']) > 0:
    if not args['--all']:
        for st in args['<st>']:
            if st in all_storage_lst:
                print(colored('      - Storage "' + st + '" is valid.', 'green'))
                storage_lst.append(st)
            else:
                print(colored('      - Storage "' + st + '" is not a valid Storage/Autochanger.', 'red'))
                print(colored('        - Exiting.\n', 'red'))
                sys.exit(1)
    else:
        storage_lst = all_storage_lst

# Create a dictionary of Storage resources defined in the Director
# ----------------------------------------------------------------
host_dict = {}
print(colored('\n  - Determining IP address for ' + ('Director and ' if args['--all'] else '') \
      + ('All ' if len(storage_lst) > 1 else '') + 'Storage resource' + ('s' if len(storage_lst) > 1 else '') \
      + ' and creating unique host list.', 'white', attrs=['bold']))

if args['--all'] or args['--dir']:
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
        print('        - Adding Storage "' + st + '" (' + ip + ') to list of hosts to retrieve report from.')
        host_dict[st] = ip
    else:
        print('        - IP address for ' + ('Storage ' if not st == 'DIR' else 'local ') \
               + '"' + st + '" (' + ip + ') already in list. Skipping...')

# Now get the reports from each host in the host_dict dictionary
# --------------------------------------------------------------
if len(host_dict) == 0:
    print(colored('\n  - There are no valid Storages/Autochangers to gather reports from!', 'red'))
else:
    print(colored('\n  - Attempting to retrieve report' + ('' if len(host_dict) == 1 else 's') \
        + ' from server' + ('' if len(host_dict) == 1 else 's') \
        + ' with IP address' + ('' if len(host_dict) == 1 else 'es') \
        + ': ', 'white', attrs=['bold'])+ colored(", ".join(host_dict.values()), 'yellow'))

    # Use a dictionary comprehension to invert the keys and values
    # of the host_dict dictionary so we can get the name of the
    # Storage (or 'Director' in the case of a Director IP), using
    # the IP address as the key.
    # https://peps.python.org/pep-0274/
    # https://stackoverflow.com/a/18043402
    # ------------------------------------------------------------
    rev_host_dict = {v: k for k, v in host_dict.items()}

    # Iterate through the unique hosts (IP addresses) and then upload
    # the bsys_report.pl script, run it, and download the report
    # ---------------------------------------------------------------
    reports = 0
    for host in host_dict.values():
        print(colored('    - Working on host: ', 'green') + colored(host + ' (' + rev_host_dict[host] + ')', 'yellow'))

        # Upload the local bsys report generator script to the remote host with
        # a timestamped filename to prevent overwrites or any permission issues
        # ---------------------------------------------------------------------
        print('      - Uploading ' + local_script_dir + ('/' if local_script_dir != './' else '') + local_script_name + ' to ' + host + ':' + remote_tmp_dir)
        try:
            cmd = f"scp {local_script_dir}/{local_script_name} {ssh_user}@{host}:{remote_script_name}"
            status = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        except Exception as e:
            errors += 1
            print(colored('        - ' + str(e), 'red'))
            print(colored('          - Problem uploading ' + local_script_dir + '/' \
                  + local_script_name + ' to ' + remote_tmp_dir, 'red'))
            print(colored('            - Skipping this host "' + host + '"!\n', 'red'))
            continue
        print(colored('        - Done', 'green'))

        # Run the uploaded bsys report generator script and
        # capture the output to get the name of the report file
        # -----------------------------------------------------
        # Set up and open the ssh connection to the host
        # ----------------------------------------------
        try:
            print('      - Setting up ssh connection')
            ssh = SSHClient()
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(AutoAddPolicy())
            ssh.connect(host, username=ssh_user, timeout=5, password=ssh_priv_key_pass)
        except Exception as e:
            errors += 1
            print(colored('        - ' + str(e), 'red'))
            print(colored('          - Problem setting up ssh connection', 'red'))
            continue
        print(colored('        - Done', 'green'))
        print('      - Running ' + host + ':' + remote_script_name \
              + (' -s' if rev_host_dict[host] != 'Director' else '') + ' -o ' + remote_tmp_dir)
        remote_cmd = remote_script_name + (' -s' if rev_host_dict[host] != 'Director' else '') + ' -o ' + remote_tmp_dir
        try:
            # Only query storages if we are running on a Director
            # ---------------------------------------------------
            stdin, stdout, stderr = ssh.exec_command(remote_cmd)
            result = stdout.readlines()
        except Exception as e:
            errors += 1
            print(colored('        - ' + str(e), 'red'))
            print(colored('        - Problem encountered while trying to run remote script ' \
                  + host + ':' + remote_script_name, 'red'))
            print(colored('          - Skipping this host "' + host + '"!\n', 'red'))
            continue
        print(colored('        - Done', 'green'))

        # Close the ssh connection
        # ------------------------
        ssh.close()

        # Strip the comma off of the name that
        # was captured when the script was run
        # ------------------------------------
        remote_dl_file = result[0].split()[3].replace(',', '')

        # Create a filename for the downloaded bsys report that is
        # prepended with 'Director' or the Storage name depending on
        # which type it is, followed by the IP address. If '--all' or
        # '--dir' was used on the command line, the Director IP will
        # always be first in the dictionary because we add it first.
        # -----------------------------------------------------------
        local_dl_file = local_tmp_dir + '/' + rev_host_dict[host] + '-' + host + '-' + os.path.basename(remote_dl_file)

        # Now download the report
        # -----------------------
        print('      - Retrieving report ' + host + ':' + remote_dl_file)
        try:
            cmd = f"scp {ssh_user}@{host}:{remote_dl_file} {local_dl_file}"
            status = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            reports += 1
        except Exception as e:
            errors += 1
            print(colored('        - ' + str(e), 'red'))
            print(colored('        - Problem encountered while trying to download remote bsys report ' \
                  + host + ':' + remote_dl_file + '\n          as: ' + local_dl_file, 'red'))
            print(colored('          - Skipping this host "' + host + '"!\n', 'red'))
            continue
        print(colored('        - Done', 'green'))

# Create a tarball of all the downloaded bsys reports.
# Skip tarring if there is only one file, and report
# the results.
# ----------------------------------------------------
if reports == 0:
    print(colored('\n  - No bsys reports retrieved.', 'red'))
elif reports == 1:
    print(colored('\n  - Only one bsys report retrieved.', 'white', attrs=['bold']))
    print('    - Not creating a tarball of one bsys report file.')
    print('    - Prepending bsys report filename with ticket mask "' + mask + '"')

    # When only one report is receieved the 'host' variable will
    # be leftover from the for loop above and is safe to use here
    # -----------------------------------------------------------
    new_local_dl_file = local_tmp_dir + '/' + mask + '_' + rev_host_dict[host] + '-' + host + '-' + os.path.basename(remote_dl_file)
    cmd = f"mv {local_dl_file} {new_local_dl_file}"
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    print(colored('\n  - The one bsys report file is here: ', 'white', attrs=['bold']) + colored(new_local_dl_file, 'yellow'))
else:
    tar_err = False
    tar_filename = mask + '_' + now + '.tar'
    print(colored('\n  - Creating tarball of all bsys reports.', 'white', attrs=['bold']))
    try:
        cmd = f"cd {local_tmp_dir}; tar -cf {tar_filename} *.gz"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    except:
        errors += 1
        tar_err = True
        print(colored('    - Problem encountered while trying to tar bsys reports.', 'red'))
        print(colored('    - Please check the local directory: ', 'red') + local_tmp_dir)
    if tar_err == False:
        print(colored('    - Done\n', 'green'))
        if reports >= 1:
            print(colored('  - ' + ('All ' if reports > 1 else 'The ') + 'bsys report' \
                  + ('s' if reports > 1 else '') + (' is' if reports == 1 else ' are') \
                  + ' available in directory: ', 'white', attrs=['bold']) + colored(local_tmp_dir, 'yellow'))
        print(colored('\n  - Archive (tar) of all reports available as: ', 'white', attrs=['bold']) \
              + colored(local_tmp_dir + '/' + tar_filename, 'yellow'))
if errors > 0:
    print(colored('  - (' + str(errors) + ') Error' + ('s were' if errors > 1 else ' was') \
          + ' detected during script run. Please check the script output above!', 'red', attrs=['bold']))
if '127.0.0.1' in host_dict.values():
    print(colored('\n  - WARNING:', 'white', attrs=['bold']))
    print(colored('    - The IP address \'127.0.0.1\' was detected in your Director\'s configuration.', 'red'))
    print(colored('    - The report from this host might not be from the server you expect!', 'red'))
    print(colored('    - Please do not use \'localhost\' or \'127.0.0.1\' for any of your \'Address=\' settings!', 'red'))
print(colored('- Script complete.\n', 'green', attrs=['bold']))
