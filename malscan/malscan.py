###################################################################################
#   Malscan: Threat Intel tool to check file/hash reputation also support file uploads to VirusTotal
#   Currently supports VirusTotal only, plan to add support for MalwareBazaar and Malshare
#   Created by: ReverseThrottle
#   09/02/22
#   Resource: https://developers.virustotal.com/reference/overview
#

import argparse
import hashlib
import datetime
import time
import requests
import tabulate
from hurry.filesize import size


# Global variables needed
APIKEY = None                                               # TODO Change this to your VT api key
CHECKFILESUB = None                                         # Variable used for checking last analysis of sample
scan_file_url = 'https://www.virustotal.com/api/v3/files'   # VT api url file check
                                                            # Headers used for VT api
headers = {
    "Accept": "application/json",
    "x-apikey": APIKEY
}

# Arg Parsing and help
parser = argparse.ArgumentParser(description='Scan/Upload a file to VT and get results returned')
# File argument
parser.add_argument('--file', '-f', help='File to upload')
# Hash argument
parser.add_argument('--hash', help='Hash string to upload')
# Retrieves PE info from VT
parser.add_argument('--peinfo', help='Shows info about PE (set as True)')
# Retrieve sandbox information from VT
parser.add_argument('--sandbox', help='Returns info about sandbox results (set as True)')

# Colors used in script for readability
class colors:
    reset = '\033[0m'
    reverse = '\033[07m'
    bold ='\033[01m'
    orange = '\033[33m'
    blue = '\033[34m'
    purple = '\033[35m'
    lightgreen = '\033[92m'
    lightblue = '\033[94m'
    pink = '\033[95m'
    lightcyan = '\033[96m'
    red = '\033[31m'
    green = '\033[32m'
    cyan = '\033[36m'
    lightgrey = '\033[37m'
    darkgrey = '\033[90m'
    lightred = '\033[91m'
    yellow = '\033[93m'


def main(args):

    if args.hash:
        ScanHash(args)
    elif args.file:
        ScanFile(args)
    else:
        print(f'In order to run you must include a file hash or path to file to scan')
        exit()


def ScanHash(args):
    # VT url api
    check_file_url = 'https://www.virustotal.com/api/v3/files/'
    print(f'{colors.bold}==========================================================================================={colors.reset}')
    print(f'Checking Hash: {colors.cyan}{args.hash}\n{colors.reset}')
    check_file_url += args.hash
    # Get response from VT
    response = requests.get(check_file_url, headers=headers)
    if response.status_code == 200:
        # Return value converted to json format
        result = response.json()
        # Check last analysis of file (if greater than 3 days it will notify you)
        CheckLastSubbmission(result, args)
        # Returns basic information about the file such as hashes, verdicts, and metadata
        GetBasicFileInfo(result)
        # If PEINFO argument is passed
        if args.peinfo:
            # Gets IAT, Resources, Sections, and Header of PE file
            GetPEInfo(result)
        # If sandbox argument is passed checks sandbox verdicts
        if args.sandbox:
            GetSandboxResults(result)
        exit()
    else:
        print(f"{colors.orange}Could not retrieve file hash...{colors.reset}")
        print(f"{colors.orange}You will need to upload file to VT{colors.reset}")
        exit()


def ScanFile(args):
    check_file_url = 'https://www.virustotal.com/api/v3/files/'

    print(f'{colors.bold}==========================================================================================={colors.reset}')
    print(f'Calculating hash of {colors.cyan}{args.file}{colors.reset}...')
    # Calculates hash of file
    sha256hash = HashFile256(args.file)
    print(f'SHA256 hash: {colors.cyan}{sha256hash}{colors.reset}')
    check_file_url += sha256hash
    print('Checking VTs database for hash...\n')
    # Uses hash to check VT for hash before trying to upload file to VT
    response = requests.get(check_file_url, headers=headers)
    result = response.json()
    if response.status_code != 404:
        # If hash is found
        # It will check the last time it was analyzed (if older than 3 days it will notify you)
        CHECKFILESUB = CheckLastSubbmission(result, args)
        # If True sample will be submitted if False sample will not be submitted to VT
        if CHECKFILESUB is True:
            # Used to send sample to VT
            file = UploadFile(args.file)
            files = {"file": file}
            response = requests.post(scan_file_url, files=files, headers=headers)
            # Checks response of VT
            if response.status_code == 200:
                print(f'{colors.cyan}File is queued on VirusTotal....\nWaiting...{colors.reset}')
                # Waits for VT to analyze file
                time.sleep(60)
                # Checks VT again for updated analysis
                response = requests.get(check_file_url, headers=headers)
                if response.status_code == 200:
                    # Converts response to json
                    result = response.json()
                    # Return basic information regarding file
                    GetBasicFileInfo(result)
                    # If PEINFO argument is passed will get PE information
                    if args.peinfo:
                        GetPEInfo(result)
                    # If sandbox argument is passed checks sandbox verdicts
                    if args.sandbox:
                        GetSandboxResults(result)
            else:
                print(f'{colors.red}Failed to upload file to VT{colors.reset}')
                exit()
        else:
            # Checks basic file information from VT
            GetBasicFileInfo(result)
            # If PEINFO argument is passed will get PE information
            if args.peinfo:
                GetPEInfo(result)
            # If sandbox argument is passed checks sandbox verdicts
            if args.sandbox:
                GetSandboxResults(result)
    else:
        # If file hash cannot be found it will ask user if they want to upload file to VT
        print(f'{colors.orange}Could not retrieve file hash!\nWould you like to upload file to VT?\n{colors.reset}')
        # Gets user input
        userInput = input("Please select y/n: \n")
        if userInput == 'y':
            file = UploadFile(args.file)
            files = {"file": file}
            response = requests.post(scan_file_url, files=files, headers=headers)
            # Checks response of VT
            if response.status_code == 200:
                print(f'{colors.cyan}File is queued on VirusTotal....\nWaiting...{colors.reset}')
                time.sleep(60)
                response = requests.get(check_file_url, headers=headers)
                if response.status_code == 200:
                    # Converts response to json
                    result = response.json()
                    # Gets basic file information
                    GetBasicFileInfo(result)
                    # If PEINFO argument is passed it retrieves PE information
                    if args.peinfo:
                        GetPEInfo(result)
                    # If sandbox argument is passed checks sandbox verdicts
                    if args.sandbox:
                        GetSandboxResults(result)
            else:
                print(f"{colors.red}Failed to upload file to VT{colors.reset}")
                exit()
        elif userInput == 'n':
            exit()
        else:
            print(f'Not a valid answer!\n')
            exit()


def GetBasicFileInfo(result):
    GetVTLink(result)
    # Retrieves MD5, SHA-256, SHA-1 hashes
    print(f'{colors.bold}MD5: {colors.reset}{colors.cyan}{result.get("data").get("attributes").get("md5")}{colors.reset}')
    print(f'{colors.bold}SHA-1: {colors.reset}{colors.cyan}{result.get("data").get("attributes").get("sha1")}{colors.reset}')
    print(f'{colors.bold}SHA-256: {colors.reset}{colors.cyan}{result.get("data").get("attributes").get("sha256")}\n{colors.reset}')
    # Retrieves File type, magic bytes, type tag, size, and number of times submitted to VT
    print(f'{colors.bold}File Type: {colors.reset}{colors.cyan}{result.get("data").get("attributes").get("type_description")}{colors.reset}')
    print(f'{colors.bold}Magic: {colors.reset}{colors.cyan}{result.get("data").get("attributes").get("magic")}{colors.reset}')
    print(f'{colors.bold}Type Tag: {colors.reset}{colors.cyan}{result.get("data").get("attributes").get("type_tag")}{colors.reset}')
    # Using python library hurry.filesize to convert bytes into MB, KB, etc - https://pypi.org/project/hurry.filesize/
    print(f'{colors.bold}Size: {colors.reset}{colors.cyan}{size(result.get("data").get("attributes").get("size"))}{colors.reset}')
    print(f'{colors.bold}Times Submitted: {colors.reset}{colors.cyan}{result.get("data").get("attributes").get("times_submitted")}\n{colors.reset}')
    # Retrieves the count of malicious hits and count of undetected hits
    print(f'{colors.red}Malicious count: {result.get("data").get("attributes").get("last_analysis_stats").get("malicious")}{colors.reset}')
    print(f'{colors.green}Undetected count: {result.get("data").get("attributes").get("last_analysis_stats").get("undetected")}{colors.reset}')

    # Checks if there is a malicious hit
    if result.get("data").get("attributes").get("last_analysis_stats").get("malicious") == 0:
        # We pass as there will be no threat info if not malicious
        pass
    else:
        # Prints threat label and categories
        print(f'{colors.bold}Threat Label: {colors.reset}{colors.cyan}{result.get("data").get("attributes").get("popular_threat_classification").get("suggested_threat_label")}{colors.reset}')
        threat_cat = result.get("data").get("attributes").get("popular_threat_classification").get("popular_threat_category")
        header = threat_cat[0].keys()
        rows = [x.values() for x in threat_cat]
        print(f'{colors.cyan}{tabulate.tabulate(rows, header)}\n{colors.reset}')
    # Checks first submission, last submission, and last analysis
    last_sub = result.get("data").get("attributes").get("last_submission_date")
    first_sub = result.get("data").get("attributes").get("first_submission_date")
    last_analysis = result.get("data").get("attributes").get("last_analysis_date")
    print(f'{colors.bold}First Submission Date: {colors.reset}{colors.cyan}{datetime.datetime.fromtimestamp(first_sub)}{colors.reset}')
    print(f'{colors.bold}Last Submission Date: {colors.reset}{colors.cyan}{datetime.datetime.fromtimestamp(last_sub)}{colors.reset}')
    print(f'{colors.bold}Last Analysis Date: {colors.reset}{colors.cyan}{datetime.datetime.fromtimestamp(last_analysis)}{colors.reset}')
    print(f'{colors.bold}==========================================================================================={colors.reset}')
    # This will print vendors that detected sample as malicious and show related information
    av_result = result.get("data").get("attributes").get("last_analysis_results")
    for i in av_result:
        if av_result[i].get("category") == "malicious":
            # Prints AV egine information such as version and engine name
            print(f'AV Engine: {colors.cyan}{av_result[i].get("engine_name")}{colors.reset}\nAV Version: {colors.cyan}{av_result[i].get("engine_version")}{colors.reset}\nDetection: {colors.red}{av_result[i].get("category")}{colors.reset}\nResult: {colors.cyan}{av_result[i].get("result")}{colors.reset}')
            print(f'{colors.bold}==========================================================================================={colors.reset}')


def GetPEInfo(result):
    # Checks file extension of sample if not exe or dll we cannot retrieve PE information
    extension = result.get("data").get("attributes").get("type_extension")
    if extension == 'exe' or extension == "dll":
        print(f'{colors.bold}PE Header Info: {colors.reset}')
        # Check the machine type against MSDN's codes - https://learn.microsoft.com/en-us/windows/win32/debug/pe-format - Under Machine Types subtitle
        machine_type = (f'{result.get("data").get("attributes").get("pe_info").get("machine_type")}')
        if machine_type == '467':
            machine_type = "Matsushita AM33"
        elif machine_type == '34404':
            machine_type = "x64"
        elif machine_type == '448':
            machine_type = "ARM Little Endian"
        elif machine_type == '43620':
            machine_type = "ARM64 Little Endian"
        elif machine_type == '332':
            machine_type = "Intel 386"
        elif machine_type == '452':
            machine_type = "ARM Thumb-2 Little Endian"
        elif machine_type == '3771':
            machine_type = "EFI Byte Code"
        elif machine_type == '512':
            machine_type = "Intel Itanium"
        elif machine_type == '25138':
            machine_type = "LoongArch 32-bit"
        elif machine_type == '25188':
            machine_type = "LoongArch 64-bit"
        elif machine_type == '36929':
            machine_type = "Mitsubishi M32R"
        elif machine_type == '614':
            machine_type = "MIPS16"
        elif machine_type == '870':
            machine_type = "MIPS with FPU"
        elif machine_type == '1126':
            machine_type = "MIPS16 with FPU"
        elif machine_type == '496':
            machine_type = "Power PC Little Endian"
        elif machine_type == '497':
            machine_type = "Power PC with Floating Point Support"
        elif machine_type == '358':
            machine_type = "MIPS Little Endian"
        elif machine_type == '20530':
            machine_type = "RISC-V 32-bit"
        elif machine_type == '20580':
            machine_type = "RISC-V 64-bit"
        elif machine_type == '20776':
            machine_type = "RISC-V 128-bit"
        elif machine_type == '418':
            machine_type = "Hitachi SH3"
        elif machine_type == '419':
            machine_type = "Hitachi SH3 DSP"
        elif machine_type == '422':
            machine_type = "Hitachi SH4"
        elif machine_type == '424':
            machine_type = "Hitachi SH5"
        else:
            pass
        print(f'{colors.bold}Machine Type: {colors.reset}{colors.cyan}{machine_type}{colors.reset}')
        # Gets timestamp of file
        timestamp = result.get("data").get("attributes").get("pe_info").get("timestamp")
        print(f'{colors.bold}Compilation Timestamp: {colors.reset}{colors.cyan}{datetime.datetime.fromtimestamp(timestamp)}{colors.reset}')
        GetEntryPoint(result)
        # Prints number of sections
        sections_count = len(result.get("data").get("attributes").get("pe_info").get("sections"))
        print(f'{colors.bold}Number of Sections: {colors.reset}{colors.cyan}{sections_count}\n{colors.reset}')
        GetPESections(result)
        GetIAT(result)
        GetPEResource(result)
    else:
        print(f'{colors.orange}File is not executable.. It is of type: {result.get("data").get("attributes").get("type_description")}{colors.reset}')


def GetVTLink(result):
    # Provides a link to view sample on browser if desired
    vt_link = "https://www.virustotal.com/gui/file/"
    sample_hash = result.get("data").get("attributes").get("sha256")
    vt_link += sample_hash
    print(vt_link)


def GetEntryPoint(result):
    # Retrieves the entry point returned from VT
    ep = result.get("data").get("attributes").get("pe_info").get("entry_point")
    print(f'{colors.bold}Entry Point:{colors.reset}{colors.cyan}{ep}{colors.reset}')


def GetPEResource(result):
    print(f'{colors.bold}Resources: {colors.reset}')
    # Grabs resource information and prints results in formatted table
    # For my table I am using tabulate - https://pypi.org/project/tabulate/
    resource_details = result.get("data").get("attributes").get("pe_info").get("resource_details")
    header = resource_details[0].keys()
    rows = [x.values() for x in resource_details]
    print(f'{colors.cyan}{tabulate.tabulate(rows, header)}\n{colors.reset}')


# Will grab Sections info from PE file
def GetPESections(result):
    print(f'{colors.bold}Sections: {colors.reset}')
    # Gets section information from json return
    sections = result.get("data").get("attributes").get("pe_info").get("sections")
    header = sections[0].keys()
    rows = [x.values() for x in sections]
    print(f'{colors.cyan}{tabulate.tabulate(rows, header)}\n{colors.reset}')


# Checks if last submission is older than 3 days
def CheckLastSubbmission(result, args):
    # Gets last analysis from VT
    lastSub = result.get("data").get("attributes").get("last_analysis_date")
    # Converts to datetime
    lastSub = datetime.datetime.fromtimestamp(lastSub)
    # Gets current date time
    curr_date = datetime.datetime.today()

    # Will - values and check if less than -3
    check = lastSub - curr_date
    if check.days < -3:
        # If it was a hash upload all we can do is inform user to re-submit if possible
        if args.hash:
            print(f"{colors.orange}You should re-submit sample to VT last submission was over 3 days ago!{colors.reset}")
        # If file ask user to re-submit file
        elif args.file:
            print(f'{colors.orange}Sample has not been analyzed in over 3 days!{colors.reset}')
            print(f"{colors.orange}Would you like to re-submit sample to VT?{colors.reset}")
            # Get User input (Y or N)
            userInput = input("Please enter y/n: \n")
            # If yes rescan file and return new results
            # return value is used within ScanFile functions
            if userInput == "y":
                output = True
                return output
            elif userInput == "n":
                output = False
                return output
            else:
                print(f"{colors.orange}Not a valid answer!{colors.reset}")
                output = False
                return output
    else:
        print(f"{colors.orange}Sample has been recently scanned!{colors.reset}")
        output = False
        return output


# Gets IAT value taken is response from VT
def GetIAT(result):
    print(f'{colors.bold}Import Address Table: {colors.reset}')
    # Grabs import table from PE section within json return
    import_list = result.get("data").get("attributes").get("pe_info").get("import_list")
    # First loop is to print the library name
    for i in range(len(import_list)):
        print(f'{colors.bold}Library: {colors.reset}{colors.cyan}{import_list[i].get("library_name")}{colors.reset}')
        imported_func_list = import_list[i].get("imported_functions")
        # Second is to print dll file names
        for x in range(len(imported_func_list)):
            print(f'\t{colors.cyan}{imported_func_list[x]}\n{colors.reset}')


# Gets Sandbox verdicts from VT as input
def GetSandboxResults(result):
    # Gets sandbox info from json response
    sandbox_verdict = result.get("data").get("attributes").get("sandbox_verdicts")
    if sandbox_verdict != None:
        # Loops through return and prints to screen
        for key, value in sandbox_verdict.items():
            print("\n")
            print(f"{colors.bold}Sandbox : ", key, f"{colors.reset}")
            for ckey in value:
                print(f"{colors.cyan}{ckey} :", f"{value[ckey]}{colors.reset}")
    else:
        print(f'{colors.orange}There is no Sandbox verdicts{colors.reset}')


# MD5 hash function which returns the hash of a file
def HashFile(file):
    with open(file, 'rb') as f:
        data = f.read()
        md5hash = hashlib.md5(data).hexdigest()
    return md5hash


# SHA256 hash function which returns file hash
def HashFile256(file):
    with open(file, 'rb') as f:
        data = f.read()
        sha256hash = hashlib.sha256(data).hexdigest()
    return sha256hash


# Returns raw file data used to upload sample to VT
def UploadFile(file):
    with open(file, 'rb') as f:
        file = f.read()
    return file


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main(parser.parse_args())
