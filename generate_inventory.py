from sys import exit
import argparse
import json
from openpyxl import Workbook
import xmltojson
import requests
from getpass import getpass
from base64 import b64encode
from tls_detection_processor import process_tls_detections, output_tls_inventory
from ssh_detection_processor import process_ssh_detections, output_ssh_inventory

def get_qualys_detections(baseurl: str, username: str, password: str, qids=None) -> list:
    more_data = True
    full_data = []
    if qids is None:
        qids = [38116, 38704,38047]
    auth_string = b64encode(f'{username}:{password}'.encode()).decode()
    headers = {'X-Requested-With': 'python/requests', 'Authorization': f'Basic {auth_string}'}
    detections_url = (f'{baseurl}/api/2.0/fo/asset/host/vm/detection?action=list&show_igs=1&'
                      f'qids={','.join(str(q) for q in qids)}')
    print('Getting detection data', end='')
    while more_data:
        response = requests.get(url=detections_url, headers=headers)
        if response.status_code == 200:
            jdata = json.loads(xmltojson.parse(response.text))
            if 'WARNING' in jdata['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE'].keys():
                if 'URL' not in jdata['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE']['WARNING'].keys():
                    more_data = False
                else:
                    detections_url = jdata['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE']['WARNING']['URL']
            else:
                more_data = False
            full_data += jdata['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE']['HOST_LIST']['HOST']
        else:
            print(' ERROR\nCould not get detection data')
        print('.', end='')
    print(' Finished')
    return full_data


def output_inventory(inventory: list, filename: str):

    if filename.split('.')[len(filename.split('.'))-1] != 'xlsx':
        filename = f'{filename}.xlsx'

    wb = Workbook()
    output_tls_inventory(wb, inventory)
    output_ssh_inventory(wb, inventory)

    print('Saving Workbook')
    wb.save(filename)


# Script entry point
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--username', help='API Username')
    parser.add_argument('--password', help='API Password (or \'-\' to enter password interactively)')
    parser.add_argument('--apiurl', help='API Base URL (e.g. https://qualysapi.qualys.com)')
    parser.add_argument('--outputfile', help='Name of output file')

    args = parser.parse_args()

    if args.username is None:
        print('ERROR: No username specified')
        exit(1)
    if args.password is None:
        print('ERROR: No password specified')
        exit(1)
    if args.apiurl is None:
        print('ERROR: No API URL specified')
        exit(1)
    if args.outputfile is None:
        print('ERROR: No output filename specified')
        exit(1)

    if args.password == '-':
        args.password = getpass(f'Enter password for user {args.username}: ')

    detection_data = get_qualys_detections(username=args.username, password=args.password, baseurl=args.apiurl)

    print('Building inventory')
    full_inventory = process_ssh_detections(detection_data)
    full_inventory += process_tls_detections(detection_data)

    print('Writing output file')
    output_inventory(inventory=full_inventory, filename=args.outputfile)

    print('Script complete')
