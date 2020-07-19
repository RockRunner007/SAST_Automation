import requests
import os
import logging
import time
from datetime import date

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

def get_team_id(token):
    headers = {
        'Accept': 'application/json;v=1.0',
        'Authorization': f"Bearer {token}"
    }
    full_team_name = f"\\CxServer\\SP\\Company\\{os.environ['CHECKMARX_TEAM_NAME']}"
    resp = requests.get("{URL}/cxrestapi/auth/teams", headers=headers)
    teams = resp.json()
    for team in teams:
        if team['fullName'] == full_team_name:
            logging.info(f"Successfully retrieved team id for team: {os.environ['CHECKMARX_TEAM_NAME']}")
            return team['id']
    logging.error(f"Failed to get team id for team name: {os.environ['CHECKMARX_TEAM_NAME']}")
    exit(1)

def get_project(token, teamId):
    headers = {
        'Accept': 'application/json;v=1.0',
        'Authorization': f"Bearer {token}"
    }
    payload = {
        'projectName': os.environ['CHECKMARX_PROJECT_NAME'],
        'teamId': teamId
    }
    resp = requests.get('{URL}/cxrestapi/projects', headers=headers, params=payload)
    if resp.status_code == 200:
        #logging.info(f"Successfully retrieved project: {os.environ['CHECKMARX_PROJECT_NAME']}")
        return resp.json()[0]
    else:
        logging.error(f"Failed to get projects. Status Code: {resp.status_code}")
        exit(1)

def get_recent_scans(token, projectId):
    headers = {
        'Accept': 'application/json;v=1.0',
        'Authorization': f"Bearer {token}"
    }
    payload = {
        'projectId': projectId,
        'scanStatus': 'Finished',
        'last': 3
    }
    resp = requests.get('{URL}/cxrestapi/sast/scans', params=payload, headers=headers)
    if resp.status_code == 200:
        #logging.info("Successfully retrieved recent scans.")
        return resp.json()
    else:
        logging.error(f"Failed to get recent scans.  Status Code: {resp.status_code}")
        exit(1)

def get_report_status(token, reportId):
    headers = {
        'Accept': 'application/json;v=1.0',
        'Authorization': f"Bearer {token}"
    }
    resp = requests.get(f"{URL}/cxrestapi/reports/sastScan/{reportId}/status", headers=headers)
    report_status = resp.json()['status']['value']
    logging.info(f"Report Status: {report_status}")
    if report_status == 'InProgress':
        return True
    else:
        return False

def download_report(token, reportId):
    headers = {
        'Authorization': f"Bearer {token}",
        'Accept': 'application/pdf'
    }
    today = date.today()
    report_filename = f"{os.environ['CHECKMARX_PROJECT_NAME']}-{today.strftime('%m-%d-%Y')}.pdf"
    resp = requests.get(f"{URL}/cxrestapi/reports/sastScan/{reportId}", headers=headers)
    if resp.status_code == 204:
        logging.info("Waiting for report generation...")
        time.sleep(5)
        download_report(token, reportId)
    else:
        logging.info("Report successfully generated")
        open(report_filename, 'wb').write(resp.content)

def generate_report(token, scan):
    headers = {
        'Accept': 'application/json;v=1.0',
        'Authorization': f"Bearer {token}"
    }
    payload = {
        'reportType': 'PDF',
        'scanId': scan['id']
    }
    resp = requests.post('{URL}/cxrestapi/reports/sastScan', headers=headers, json=payload)
    if resp.status_code == 202:
        logging.info("Sucessfully submitted report generation request")
        return resp.json()['reportId']
    else:
        logging.error(f"Failed to generate report. Status Code: {resp.status_code}")
        exit(1)

def download_stats(token, scan):
    headers = {
        'Accept': 'application/json;v=1.0',
        'Authorization': f"Bearer {token}"
    }
    resp = requests.get(f"{URL}/cxrestapi/sast/scans/{scan['id']}/resultsStatistics", headers=headers)
    if resp.status_code == 200:
        logging.info("Successfully downloaded stats")
    else:
        logging.error('Failed to download scan stats')
    open('stats.json', 'w').write(resp.text)

def main():
    configure_logging()
    token = get_access_token()
    teamId = get_team_id(token)
    project = get_project(token, teamId)
    scan_list = get_recent_scans(token, project['id'])
    reportId = generate_report(token, scan_list[0])
    while get_report_status(token, reportId):
        time.sleep(5)
        logging.info("Waiting for report generation...")
    else:
        download_report(token, reportId)
    download_stats(token, scan_list[0])

if __name__ == "__main__":
    main()