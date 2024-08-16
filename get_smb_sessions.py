#!/usr/bin/env python3
import urllib3
import configparser
import sys
import os
import json
import aiohttp
import asyncio

config_file ="smb_share_evictor.conf"

# Load and check config file
def config_check(config):
    # Check if CLUSTER_ADDRESS is set in the config
    if not config["CLUSTER"].get("CLUSTER_ADDRESS"):
        print("Error: CLUSTER_ADDRESS is not set in the config file.")
        sys.exit()
    else:
        CLUSTER_ADDRESS = config["CLUSTER"]["CLUSTER_ADDRESS"]

    # Check if TOKEN is set in the config
    if not config["CLUSTER"].get("TOKEN"):
        print("Error: TOKEN is not set in the config file.")
        sys.exit()
    else:
        TOKEN = config["CLUSTER"]["TOKEN"]

    USE_SSL = config["CLUSTER"].getboolean('USE_SSL')
    return CLUSTER_ADDRESS, TOKEN, USE_SSL

async def get_smb_sessions(session):
    url = f"https://{CLUSTER_ADDRESS}/api/v1/smb/sessions/"
    try:
        async with session.get(url, headers=HEADERS, ssl=USE_SSL) as response:
            # Attempt to read and decode JSON, but catch ContentTypeError
            sessions = await response.json()
    except aiohttp.client_exceptions.ContentTypeError as e:
        # Print the raw response text that caused the error
        raw_content = await response.text()
        print(f"Failed to decode JSON. Raw content was: {raw_content}")
        raise e  # Re-raise the exception after logging the raw content

    next_page = sessions['paging'].get('next')
    tasks = []
    tasks.append(session.get(url, headers=HEADERS, ssl=USE_SSL))

    # Paging support
    while next_page:
        url = f"https://{CLUSTER_ADDRESS}/api" + next_page
        tasks.append(session.get(url, headers=HEADERS, ssl=USE_SSL))
        try:
            next_page = (await (await session.get(url, headers=HEADERS, ssl=USE_SSL)).json()).get('paging', {}).get('next')
            print(f"PAGE: {next_page}")
        except aiohttp.client_exceptions.ContentTypeError as e:
            raw_content = await response.text()
            print(f"Failed to decode JSON on paging inside Paging Loop. Raw content was: {raw_content}, next Page: {next_page}")
            raise e

    responses = await asyncio.gather(*tasks)
    results = []
    for response in responses:
        try:
            result = await response.json()
            results.append(result)
        except aiohttp.client_exceptions.ContentTypeError as e:
            raw_content = await response.text()
            print(f"Failed to decode JSON in gathered response. Raw content was: {raw_content}")
            raise e

    final_result = {
        'session_infos': [session_info for item in results for session_info in item['session_infos']]
    }
    return final_result

async def main():

    global TOKEN
    global CLUSTER_ADDRESS
    global USE_SSL
    global HEADERS

    # Load config
    config = configparser.ConfigParser()

    # Check that config file exists
    if not os.path.isfile(config_file):
        print(f"ERROR - Config file '{config_file}' not found! Exiting")
        sys.exit()    

    config.read(config_file)

    # Populate info from config file
    CLUSTER_ADDRESS, TOKEN, USE_SSL = config_check(config)
    HEADERS = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    # Main async 'session' function
    async with aiohttp.ClientSession() as session:
        smb_sessions = await get_smb_sessions(session)
        session_infos = [entry for entry in smb_sessions['session_infos']]

    with open("sessions.json", "w") as file:
        json.dump(session_infos, file, indent=4)

if __name__ == "__main__":
    asyncio.run(main())