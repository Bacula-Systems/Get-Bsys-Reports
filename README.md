# get_bsys_reports.py 

- Python script that allows you to collect bsys reports from the Director, and one, several, or all of the servers defined as Storages{} or Autochangers{} in your director configuration. Automatically identifies the Director IP address and all Storage IP addresses and then scp's a bsys report generator script to identified hosts, runs the script on each host remote, and then downloads the resulting report. If more than one report is downloaded, they are tarred into one file.

```
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
```

## Example commands:
```
# get_bsys_reports.py -dir            (Get a report from the Director)
# get_bsys_reports.py -all            (Get report from Director and all Storages defined in Director configuration)
# get_bsys_reports.py -g ST_1A        (Download current bsys report generator script and get report from one Storage)
# get_bsys_reports.py ST_1 ST_2 ST_3  (Get report from three Storages)
# get_bsys_reports.py -dir ST_4       (Get reports from Director and one Storage)
```

## Screenshot of Example Run:
![get_bsys_reports-20220523_163420](https://user-images.githubusercontent.com/108133/169915835-1970b14e-557c-4715-9abe-90e06ce019e1.png)

