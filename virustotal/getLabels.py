import hashlib
import argparse
from time import sleep
from pathlib import Path
from pprint import pprint
import requests
import json
import os


API_KEY = ""

HEADERS = {"x-apikey": API_KEY}


def hash_it(file, algorithm):
    '''
    Returns hash of the file provided

    :param file: file to hash (type: str/pathlib obj) :param algorithm: algorithm to
    use for hashing (valid algorithms: sha1 | sha256 | md5) (type: str)
    :return: file hash (type: str)
    '''
    if algorithm == "sha256":
        hasher = hashlib.sha256()
    elif algorithm == "sha1":
        hasher = hashlib.sha1()
    elif algorithm == "md5":
        hasher = hashlib.md5()
    else:
        raise Exception(
            "Incompatible hash algorithm used. Choose from: sha256 | sha1 | md5")

    with open(file, 'rb') as f:
        hasher.update(f.read())
    return hasher.hexdigest()


def vt_get_data(f_hash):
    '''
    The function gets the data against the file hash provided
    from the virustotal api

    :param f_hash: sha256 of the file to scan with virustotal
    :return: requests.models.Response
    '''
    print("GETTING DATA")
    url = f"https://www.virustotal.com/api/v3/files/{f_hash}"
    while True:
        response = requests.get(url, headers=HEADERS)
        if error_handle(response):
            break
    return response


def vt_post_files(file, url="https://www.virustotal.com/api/v3/files"):
    '''
    The function uploads a file to virustotal
    for analysis and returns the response from the
    virustotal api

    :param file: file to upload for analysis :param url: url to upload
    file to (use for files larger than 32MB) :return: requests.models.Response
    '''
    with open(file, "rb") as f:
        file_bin = f.read()
    print("UPLOADING")
    upload_package = {"file": (file.name, file_bin)}
    while True:
        response = requests.post(url, headers=HEADERS, files=upload_package)
        if error_handle(response):
            break
    return response


def vt_get_analyses(response):
    '''
    The function returns the file hash of the uploaded file
    once the analysis of the uploaded file is available

    :param response: requests.models.Response
    :return: sha256 of the previously uploaded file (type: str)
    '''
    _id = response.json().get("data").get("id")
    url = f"https://www.virustotal.com/api/v3/analyses/{_id}"
    print(f"ID: {_id}")
    while True:
        print("WAITING FOR ANALYSIS REPORT")
        sleep(120)
        while True:
            response = requests.get(url, headers=HEADERS)
            if error_handle(response):
                break
        if response.json().get("data").get("attributes").get("status") == "completed":
            f_hash = response.json().get("meta").get("file_info").get("sha256")
            return f_hash


def vt_get_upload_url():
    '''
    The function returns a url to upload files larger than 32MB
    to the virustotal api
    '''
    url = "https://www.virustotal.com/api/v3/files/upload_url"
    while True:
        response = requests.get(url, headers=HEADERS)
        if error_handle(response):
            break
    return response.json()["data"]


def error_handle(response):
    '''
    The function returns True if there are no errors
    and returns False otherwise

    :param response: requests.models.Response
    :return: bool
    '''
    if response.status_code == 429:
        print("WAITING")
        sleep(120)
    if response.status_code == 401:
        raise Exception("Invalid API key")
    elif response.status_code not in (200, 404, 429):
        raise Exception(response.status_code)
    else:
        return True
    return False


def parse_response(response, file):
    '''
    The function extracts useful information from the respose JSON file
    and return it in JSON format.

    :param response: requests.models.Response
    :return: parsed data as json/dict
    '''
    json_obj = response.json().get("data").get("attributes")

    output = {}

    output["name"] = os.path.basename(file).split('/')[-1]
    output["stats"] = json_obj.get("last_analysis_stats")
    output["engine_detected"] = {}

    for engine in json_obj.get("last_analysis_results").keys():
        if json_obj.get("last_analysis_results").get(engine).get("category") != "undetected":
            output.get("engine_detected")[engine] = {}
            output.get("engine_detected")[engine]["category"] = json_obj.get(
                "last_analysis_results").get(engine).get("category")
            output.get("engine_detected")[engine]["result"] = json_obj.get(
                "last_analysis_results").get(engine).get("result")

    output["votes"] = json_obj.get("total_votes")
    output["hash"] = {"sha1": json_obj.get(
        "sha1"), "sha256": json_obj.get("sha256")}
    output["size"] = json_obj.get("size")
    output["num_detected"]=len(json_obj.get("last_analysis_results"))
    return output


def bar(parsed_response):
    '''
    The function returns a bar to visually represent the engine
    detection.

    :param parsed_response: parsed dict/json from parse_response() function
    :return: bar (type: str)
    '''
    total = 72
    undetected = parsed_response.get("stats").get("undetected")
    data = f"{'@'*undetected}{' '*(total-undetected)}"
    bar = bar = f"+{'-'*total}+\n|{data}| {undetected}/{total} did not detect\n+{'-'*total}+"
    return bar

######################################SCRIPT######################################


#parser = argparse.ArgumentParser(description="scan your files with virustotal")
#parser.add_argument("file", action="store", nargs=1, help="file to scan")

#parsed_arg = parser.parse_args()
# print(parsed_arg)

def list_all_files(path):
    """
    List all file paths

    @param path: if it is a path, just return, if dir, return paths of files in it

    Subdirectories not listed
    No recursive search
    """
    assert os.path.isfile(path) or os.path.isdir(path)

    if os.path.isfile(path):
        return [path]
    else:
        return filter(os.path.isfile, map(lambda x: '/'.join([os.path.abspath(path), x]), os.listdir(path)))
foldername=r'../dataset'
path = r'./' +foldername
for f in list_all_files(path):

    file = Path(f)

    if not file.exists():
        raise Exception("File not found")

    # calculate file hash
    f_hash = hash_it(file, "sha256")

    # get file data against the file hash
    response = vt_get_data(f_hash)

    # if data for a specific file is not available
    # upload that file to virustotal
    if response.status_code == 404:

        # The response of vt_post_files can only be parsed by vt_get_analysis.
        # vt_post_files and vt_get_analyses should be made into a single function
        # but i left the separate in case there is a need to call vt_get_analysis
        # seperatley

        if file.stat().st_size > 32000000:
            # for files larger than 32MB
            response = vt_get_data(vt_get_analyses(
                vt_post_files(file, vt_get_upload_url())))
        else:
            # for small files
            response = vt_get_data(vt_get_analyses(vt_post_files(file)))

    if response.status_code == 200:
        # parse and print response
        parsed_response = parse_response(response, file)

        pprint(parsed_response, indent=2)
        outdir = r'./virustotal'
        #outdir = r'./androidreports/'
        if not os.path.exists(outdir):
            os.makedirs(outdir)
        filename = outdir +'/'+ 'ase_dataset.json'
        listObj=[]
        if Path(filename).exists():
            with open(filename, "r") as outfile:
                listObj = json.load(outfile)
            with open(filename, "w") as outfile:
                listObj.append(parsed_response)
                json.dump(listObj, outfile)
        else:
            with open(filename, "w") as outfile:
                json.dump([parsed_response], outfile)
        print()
        print(bar(parsed_response))
    else:
        raise Exception(response.status_code)
