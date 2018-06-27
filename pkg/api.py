import requests
import json
import time
import sys

# a simple class to abstract the MetaDefender API calls
class API:

    def __init__(self):
        # an API Key is required for using MD Cloud API's (not required for Core)
        self.headers = {"apikey" : "0ee703e5c549b2d81d68643378092735"}

    # Fetch Scan Result by File Hash via MetaDefender Core
    def hashScanResult(self, file_hash):
        api_url = "http://localhost:8008/metascan_rest/hash/" + file_hash
        response = requests.get(api_url)
        if response.status_code != 200:
            print("The server returned a ", response.status_code, file=sys.stderr)
            sys.exit(1)
        data = response.json()
        report = [False, data]
        if file_hash not in data.keys():
            report[0] = True
        return report

    # Scan a File via MetaDefender Core
    def uploadFile(self, file_name):
        api_url = "http://localhost:8008/metascan_rest/file"
        files = open(file_name, "rb")
        response = requests.post(api_url, data=files)
        if response.status_code != 200:
            print("The server returned a ", response.status_code, file=sys.stderr)
            sys.exit(1)
        data = response.json()
        return data["data_id"]

    # Download Sanitized File via MetaDefender Core
    def retrieveSanitizedFile(self, file_data_id):
        api_url = "http://localhost:8008/metascan_rest/file/converted/" + file_data_id
        response = requests.get(api_url)
        if response.status_code != 200:
            print("The server returned a ", response.status_code, file=sys.stderr)
            sys.exit(1)
        return response.content

    # Fetch Scan Result (by Data ID) via MetaDefender Core
    def retrieveScanResult(self, file_data_id):
        api_url = "http://localhost:8008/metascan_rest/file/" + file_data_id
        response = requests.get(api_url)
        if response.status_code != 200:
            print("The server returned a ", response.status_code, file=sys.stderr)
            sys.exit(1)
        data = response.json()

        # Ensure that we have the full scan report, especially useful for scanning large files
        while data['scan_results']['progress_percentage'] < 100:
            response = requests.get(api_url)
            data = json.loads(response.text)
            time.sleep(1)
        return data
