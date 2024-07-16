#!/usr/bin/env python3
import argparse
import urllib3
import configparser
import asyncio
import aiohttp
import json
import requests

# Load the config file
config = configparser.ConfigParser()
config.read("share_disconnect.conf")
CLUSTER_ADDRESS = config["CLUSTER"]["CLUSTER_ADDRESS"]
TOKEN = config["CLUSTER"]["TOKEN"]
USE_SSL = config["CLUSTER"].getboolean('USE_SSL')

# Disable "Insecure HTTP" errors if certs are not available
if not USE_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json",
}

share_to_evict = "Files"

url = f"https://{CLUSTER_ADDRESS}/api/v3/smb/shares/?populate-trustee-names=true"

def get_smb_shares():
    url = f"https://{CLUSTER_ADDRESS}/api/v3/smb/shares/?populate-trustee-names=true"
    return(requests.get(url, headers=HEADERS, verify=USE_SSL).json())
    
def get_smb_sessions():
    url = f"https://{CLUSTER_ADDRESS}/api/v1/smb/sessions/?limit=1"
    sessions = requests.get(url, headers=HEADERS, verify=USE_SSL).json()
    next_page = sessions['paging'].get('next')
    tasks = []
    while next_page:
        url = f"https://{CLUSTER_ADDRESS}/api" + next_page
        print(f"URL :", url)
        paged_session = requests.get(url, headers=HEADERS, verify=USE_SSL).json()
        # print(f"SESSION_1 ",sessions_1)
        tasks.append(paged_session)
        next_page = paged_session.get('paging', {}).get('next')
    result = {
    'session_infos': [session_info for item in tasks for session_info in item['session_infos']]
    }
    # print(f"RESULT: ", result)
    return(result)


def evict_sessions(sessions):
    # print(f"SESSIONS :", sessions)
    url = f"https://{CLUSTER_ADDRESS}/api/v1/smb/sessions/close"
    for session in sessions:
        print(f"Evicting user {session['user']['name']} from share {session['share_names']}")
    

def main():
    url = f"https://{CLUSTER_ADDRESS}/api/v3/smb/shares/?populate-trustee-names=true"
    smb_sessions = get_smb_sessions()
    session_infos = [ entry for entry in smb_sessions['session_infos']]
            
    # Filter list to only include the desired share to close since "share_names" is a dict and
    # can contain multiple entries
    filtered_list = [
    {**item, "share_names": [share for share in item["share_names"] if share == share_to_evict]}
    for item in session_infos
    if "Files" in item.get("share_names", [])
    ]
    
    evict_sessions(filtered_list)
    # evict_sessions(smb_sessions)
            


if __name__ == "__main__":
    main()