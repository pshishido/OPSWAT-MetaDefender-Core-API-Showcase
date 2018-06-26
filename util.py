import hashlib
from time import gmtime, strftime

# a simple class used to provide common utility functions
class Util:

    def __init__(self):
        self.message = "Used to provide utility functions!"

    # Calculate the SHA1 hash of the given file
    def calculateFileHash(self, file_name):
        BUF_SIZE = 65536
        sha1 = hashlib.sha1()
        with open(file_name, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                sha1.update(data)
        return "{0}".format(sha1.hexdigest())

    # Determine is file is a document (i.e. it is NOT an executable or binary)
    def isDocumentFile(self, file_scan_result):
        return not (file_scan_result["file_info"]["file_type"] == "application/octet-stream" or
                    file_scan_result["file_info"]["file_type"] == "application/x-dosexec")

    # Reconstruct the sanitized raw file data. If file was a PDF, fully reconstruct
    def reconstructSanitizedFile(self, raw_file_data, file_scan_result):
        currentTime = strftime("%Y%m%dT%H%M", gmtime())
        file_bytes = bytes(raw_file_data)
        if file_scan_result["file_info"]["file_type"] == "application/pdf":
            cdr_file = open("sanitized_file_{}.pdf".format(currentTime), "wb")
        else:
            cdr_file = open("santized_file_{}.txt".format(currentTime), "wb")
        cdr_file.write(file_bytes)

    # Log the scan results - and vulnerability information, if needed - to a report file (file_scan_report.txt)
    def writeMultiScanResults(self, file_name, file_scan_result):
        currentTime = strftime("%Y%m%dT%H%M", gmtime())
        reportName = "file_scan_report_{}.txt".format(currentTime)
        md_log = open(reportName, "w")

        md_log.write("--File Information--\n")
        for key, val in file_scan_result["file_info"].items():
            if key == "display_name" and val == "":
                val = file_name
            md_log.write("-" + key + ": " + str(val) + "\n")

        md_log.write("\n--MetaDefender Multiscan Results--\n")
        for engine in file_scan_result["scan_results"]["scan_details"]:
            md_log.write(engine + ": \n")
            for k,v in file_scan_result["scan_results"]["scan_details"][engine].items():
                if v == "":
                    v = "N/A"
                md_log.write("-" + k + ": " + str(v) + "\n")

        if not len(file_scan_result["vulnerability_info"]) == 0:
            md_log.write("\n--Vulnerability Results--\n")
            md_log.write("-has_vulnerability: " + str(file_scan_result["vulnerability_info"]["result"]["detected_product"]["has_vulnerability"]) + "\n")
            md_log.write("-remediation_link: " + file_scan_result["vulnerability_info"]["result"]["detected_product"]["remediation_link"] + "\n")
            if len(file_scan_result["vulnerability_info"]["result"]["detected_product"]["vulnerabilities"]) > 0:
                for obj in file_scan_result["vulnerability_info"]["result"]["detected_product"]["vulnerabilities"]:
                    md_log.write("-description: " + obj["description"] + "\n")
                    md_log.write("-cve: " + obj["details"]["cve"] + "\n")
        md_log.close()

