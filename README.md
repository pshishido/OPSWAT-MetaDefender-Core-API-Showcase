## OPSWAT MetaDefender Core Showcase 

This program was designed to display some of the fucntionality offered by OPSWAT's MetaDefender Core API's. It will allow the user to specify a file to be scanned. We will calculate the hash of this file (SHA265 | SHA1 | MD5), and perform a hash look up to see if this exact file has been previously scanned and has an exisiting scan report - if so, we will obtain the scan results and write out a detailed report of the findings of each individual malware engines used. Additionally, if the file is a binary file, the potential vulnerability information for this file will also be written to the detailed multiscan report. In the case that the file selected to be scanned has not been previously scanned, and does not have a pre-existing scan report, the selected file will first be scanned and uploaded via the MetaDefender Core server. Next, using the unique file data ID obtained from the file upload, the scan report is fetched from the Core server. If, based upon the scan report, the selected file is a document file, CDR will be performed on it by obtaining the raw sanitized data from the Core server, which will then be reconstructed. 

To run this program:
* Use a machine running Python 3
* Ensure file selected to be scanned is in the same working directory as the source code
* In a CLI, use the command 'python main.py <file name>' to perform the logic described above on the specified file

