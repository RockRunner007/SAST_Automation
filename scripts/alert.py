import json
import requests
import os
import logging
from datetime import datetime, timedelta, timezone

def configure_logging():
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)

def get_access_token():
    headers = {
        'Accept': 'application/json;v=1.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    payload = {
        'username': os.environ['CHECKMARX_USERNAME'],
        'password': os.environ['CHECKMARX_PASSWORD'],
        'grant_type': 'password',
        'scope': 'sast_rest_api',
        'client_id': 'resource_owner_client',
        'client_secret': os.environ['checkmarx_client_secret']
    }
    resp = requests.post('{URL}/cxrestapi/auth/identity/connect/token', data=payload, headers=headers)
    if resp.status_code == 200:
        #logging.info("Successfully retrieved access token")
        return resp.json()['access_token']
    else:
        logging.error(f"Failed to get access_token.  Status Code: {resp.status_code}")
        exit(1)

def get_projects(token):
    headers = {
        'Accept': 'application/json;v=1.0',
        'Authorization': f"Bearer {token}"
    }
    resp = requests.get('{URL}/cxrestapi/projects', headers=headers)

    if resp.status_code == 200:
        #logging.info(f"Successfully retrieved projects")
        return resp.json()
    else:
        logging.error(f"Failed to get projects. Status Code: {resp.status_code}")
        exit(1)

def get_recent_scans(token, projectid):
    headers = {
        'Accept': 'application/json;v=1.0',
        'Authorization': f"Bearer {token}"
    }
    payload = {
        'projectId': projectid,
        'scanStatus': 'Finished',
        'last': 1
    }
    resp = requests.get('{URL}/cxrestapi/sast/scans',params=payload, headers=headers)

    if resp.status_code == 200:
        #logging.info("Successfully retrieved recent scans.")
        return resp.json()
    else:
        logging.error(f"Failed to get recent scans.  Status Code: {resp.status_code}")
        exit(1)

def get_team(token, teamid):
    headers = {
        'Accept': 'application/json;v=1.0',
        'Authorization': f"Bearer {token}"
    }
    resp = requests.get("{URL}/cxrestapi/auth/teams", headers=headers)
    teams = resp.json()
    for team in teams:
        if team['id'] == teamid: return team['fullName']
    return ""

def format_json(token, project, teamid, scandate, scancount):
    team = get_team(token, teamid)

    if scancount > 0: open('scans.json', 'a').write(",")
    open('scans.json', 'a').write(f"{chr(123)}{chr(34)}Product{chr(34)}: {chr(34)}{project}{chr(34)}, {chr(34)}Team{chr(34)}: {chr(34)}{team}{chr(34)}, {chr(34)}Last Scan{chr(34)}: {chr(34)}{scandate}{chr(34)}{chr(125)}")            
    return ""

def main():
    configure_logging()
    token = get_access_token()
    cutoff_time = datetime.now() - timedelta(days=int(os.environ['TIMEFRAME']))
    scancount = 0 
    open('scans.json', 'a').write("[")

    for project in get_projects(token):        
        scaninfo = get_recent_scans(token, project['id'])
        if scaninfo == []:
            format_json(token, project['name'], project['teamId'], "N/A", scancount)
            scancount +=1 
            continue

        scandate = scaninfo[0]['dateAndTime']['startedOn'].split('T')[0]
        if (datetime.fromisoformat(scandate) < cutoff_time):
            format_json(token, project['name'], project['teamId'], scandate, scancount)
            scancount +=1            
        
    open('scans.json', 'a').write("]")

if __name__ == "__main__":
    main()