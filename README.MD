# Qumulo SMB Share Session Evictor

**This tool will disconnect all sessions for the SMB share provided, which could be useful during a cluster**
**failover or other scenarios.** 

**Evicting a session will close ALL other sessions on the same Qumulo cluster that a User might also have open.**

**For example: If closing session 'Files' and user is connected to both 'Files' and 'Data' which are hosted on same Qumulo Cluster**
**then the 'Data' session will also be closed.**

**This tool also provides the ability to list all SMB sessions for a specific or all shares and the User accounts and host IP addresses of those sessions**

**Note that active SMB clients connected via UNC will immediately attempt to reconnect and this tool will not prevent this.**

## Installation

**This script was written and tested with Python 3.12.2**

- Copy all files in this repo except this readme to your local machine.
- Run `pip install -r requirements.txt`
- Edit `smb_share_evictor.conf` with your cluster's information
- Make the script executable with `chmod +x smb_share_evictor.py` (Mac, Linux)

**You'll need an API token for an account with the following RBAC rights:**

- SMB_SESSION_WRITE
- SMB_SESSION_READ
- SMB_SHARE_READ

## Helpful Qumulo Care Articles:

[How to get an Access Token](https://docs.qumulo.com/azure-administrator-guide/connecting-to-external-services/creating-using-access-tokens-to-authenticate-external-services-qumulo-core.html) 

[Qumulo Role Based Access Control](https://care.qumulo.com/hc/en-us/articles/360036591633-Role-Based-Access-Control-RBAC-with-Qumulo-Core#managing-roles-by-using-the-web-ui-0-7)

## Operation

- run the script with `/path/to/smb_share_evictor.py --share SOMESHARE --arguments`

**List of valid arguments:**

options:
  - `-h`, `--help`            show this help message and exit
  - `--verbose`, `-v`         increase output verbosity of the evict process 
  - `--config CONFIG`, `-c /path/to/CONFIG` Cluster config file. Default is `localpath/smb_share_evictor.conf`
  - `--showall`, `-a`        List all open SMB sessions on all shares in the cluster
  - `--share SHARE`, `-s SHARE`  Input the SMB share name from which to evict users

  Required options for `--share`:
  * `--list`, `-l`            List open sessions on the SMB share designated by the `--share`/`-s` argument
  * `--evict`, `-E`           Evict all sessions on the SMB share designated by the `--share`/`-s` argument

**If using the `--evict` or `-E` flag the user will be prompted for a yes/no before proceeding**