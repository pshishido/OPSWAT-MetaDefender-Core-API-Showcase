import sys
from util import Util
from api import API

def main(file_name):

    # abstract MetaDefender API calls
    api = API()

    # abstract utility functions
    util = Util()

    # SHA1 hash of the given file
    file_hash = util.calculateFileHash(file_name)

    # was this file scanned/uploaded already?
    hash_found = api.hashScanResult(file_hash)[0]

    # if so we can obtain the scan result via the file's hash
    file_scan_result = api.hashScanResult(file_hash)[1]

    if not hash_found:

        # scan/upload the file if we din't obtain a scan result via the file's hash; save the files data_id
        file_data_id = api.uploadFile(file_name)

        # obtain the scan results via the file's data_id
        file_scan_result = api.retrieveScanResult(file_data_id)

        if util.isDocumentFile(file_scan_result):

            # retrieve the sanitized raw file data (begin CDR)
            raw_file_data = api.retrieveSanitizedFile(file_data_id)

            # reconstruct the sanitized file data into binary (or revert back to PDF if file was originally a PDF)
            util.reconstructSanitizedFile(raw_file_data, file_scan_result)

    # write out the scan results to a report file (file_scan_report.txt)
    util.writeMultiScanResults(file_name, file_scan_result)

    return 0;

# pass file name as command line argument (i.e. python main.py <file name>). Ensure file is within working directory
main(sys.argv[1])