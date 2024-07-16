# Qumulo SMB Share Session Evictor

**This tool will disconnect all sessions for the SMB share provided, which could be useful during a cluster**
**failover or other scenarios.** 

**Note that active SMB clients connected via UNC will immediately attempt to reconnect and this tool will not prevent this.**

## Installation

**This script was written and test with Python 3.12.2**

- Copy all files in this repo except this readme to your local machine.
- Run `pip install -r requirements.txt`
- Edit `smb_share_evictor.conf` with your cluster's information
- Make the script executable with `chmod +x smb_share_evictor.py` (Mac, Linux)

**You'll need an API token for an account with the following RBAC rights:**

- SMB_SESSION_WRITE
- SMB_SESSION_READ
- SMB_SHARE_READ

## Helpful Qumulo Care Articles:

[How to get an Access Token](https://care.qumulo.com/hc/en-us/articles/360004600994-Authenticating-with-Qumulo-s-REST-API#acquiring-a-bearer-token-by-using-the-web-ui-0-3) 

[Qumulo Role Based Access Control](https://care.qumulo.com/hc/en-us/articles/360036591633-Role-Based-Access-Control-RBAC-with-Qumulo-Core#managing-roles-by-using-the-web-ui-0-7)

## Operation

- run the script with `/path/to/smb_share_evictor.py --share SOMESHARE --arguments`

**List of valid arguments:**

options:
  - -h, --help            show this help message and exit
  - --verbose, -v         increase output verbosity
  - --share `SHARE`, -s `SHARE`  Input the SMB share name from which to evict users
  - --list, -l            List open sessions on the SMB share designated by the --share/-s argument
  - --evict, -E           Evict all sessions on the SMB share designated by the --share/-s argument

**If using the `--evict` or `-E` flag the user will be prompted for a yes/no before proceeding**