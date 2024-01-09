from sys import exit
import argparse
import json
from openpyxl import Workbook
import xmltojson
import requests
from getpass import getpass
from base64 import b64encode


def get_qualys_data(url: str, username: str, password: str):
    auth_string = b64encode(f'{username}:{password}'.encode()).decode()
    headers = {'X-Requested-With': 'python/requests', 'Authorization': f'Basic {auth_string}'}
    response = requests.get(url=url, headers=headers)
    return response.status_code, response.text


def process_results(result_data: str):
    rows = result_data.split('\n')
    protocols = []
    protocol = {}
    for row in rows:
        # Each row (except the column header row) is one of 3 things:
        #   1.  A protocol header which shows the protocol name and its status (enabled or disabled)
        #       e.g. (TLSv1 PROTOCOL IS ENABLED)
        #   2.  The protocol Compression Method (only available if the protocol is enabled)
        #       e.g. (TLSv1\tCOMPRESSION METHOD\tNone)
        #   3.  A ciphersuite entry available in the protocol (only available if the protocol is enabled)
        #       Data is presented as 'CIPHER\tKEY-EXCHANGE\tAUTHENTICATION\tMAC\tENCRYPTION(KEY-STRENGTH)\tGRADE
        #       e.g. RC4-MD5\tRSA\tRSA\tMD5\tRC4(128)\tMEDIUM

        if row.split('\t')[0] == 'CIPHER':
            # This is the column header row, so we can skip it
            continue
        elif row.find('PROTOCOL IS') > -1:
            # Type 1 row, meaning this is a new protocol.  If we are currently processing a protocol, we now need
            # to commit that one and start a new one.
            if len(protocol) > 0:
                protocols.append(protocol)
                protocol = {}
            protocol['Name'] = row.split(' ')[0]
            protocol['Status'] = row.split(' ')[3].strip('\t')
            protocol['CompressionMethod'] = ''
            protocol['Ciphersuite'] = []
        elif row.find('COMPRESSION METHOD') > -1:
            # Type 2 row, add the compression method to the protocol dict
            protocol['CompressionMethod'] = row.split('\t')[2]
        else:
            cipher_data = row.split('\t')
            if cipher_data[4].find('(') > -1:
                encryption = cipher_data[4].split('(')[0]
                keystrength = cipher_data[4].split('(')[1].strip(')')
            else:
                encryption = cipher_data[4]
                keystrength = ''

            cipher = {
                'Name': cipher_data[0],
                'KeyExchange': cipher_data[1],
                'Authentication': cipher_data[2],
                'MAC': cipher_data[3],
                'Encryption': encryption,
                'KeyStrength': keystrength,
                'Grade': cipher_data[5]
            }
            protocol['Ciphersuite'].append(cipher)
    return protocols


def process_data(xmldata: str):
    json_data = json.loads(xmltojson.parse(xmldata))
    # The actual detection data is buried inside the returned XML (now JSON)
    # ['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE']['HOST_LIST']['HOST'] is an array of hosts
    #
    # ['DETECTION_LIST'] is a single element, not a list, containing a single ['DETECTION'] element
    # ['DETECTION'] is either a list of  detection elements for the host or a single element containing one detection
    # ['RESULTS'] is the results section within each DETECTION element

    detection_list = []
    for host in json_data['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE']['HOST_LIST']['HOST']:
        if 'DNS' not in host.keys():
            host_name = ''
        else:
            host_name = host['DNS']

        detection_data = {
            'Hostname': host_name,
            'IP': host['IP']
        }

        if type(host['DETECTION_LIST']['DETECTION']) is type([]):
            for detection in host['DETECTION_LIST']['DETECTION']:
                detection_data['Port'] = detection['PORT']
                detection_data['LastDetected'] = detection['LAST_FOUND_DATETIME']
                detection_data['Protocols'] = process_results(detection['RESULTS'])
        else:
            detection_data['Port'] = host['DETECTION_LIST']['DETECTION']['PORT']
            detection_data['LastDetected'] = host['DETECTION_LIST']['DETECTION']['LAST_FOUND_DATETIME']
            detection_data['Protocols'] = process_results(host['DETECTION_LIST']['DETECTION']['RESULTS'])

        detection_list.append(detection_data)

    next_url = None

    if 'WARNING' in json_data['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE']:
        if 'URL' in json_data['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE']['WARNING']:
            next_url = json_data['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE']['WARNING']['URL']

    return detection_list, next_url


def output_inventory(inventory: list, filename: str):
    wb = Workbook()
    ws = wb.active
    ws.title = 'Cryptographic Inventory'
    ws['A1'] = 'IP'
    ws['B1'] = 'Hostname'
    ws['C1'] = 'Port'
    ws['D1'] = 'Last Detected'
    ws['E1'] = 'Protocol'
    ws['F1'] = 'Compression Method'
    ws['G1'] = 'Cipher'
    ws['H1'] = 'Key Exchange'
    ws['I1'] = 'Authentication'
    ws['J1'] = 'MAC'
    ws['K1'] = 'Encryption'
    ws['L1'] = 'Key Strength'
    ws['M1'] = 'Grade'

    row = 2
    for i in inventory:
        for protocol in i['Protocols']:
            if protocol['Status'] == 'DISABLED':
                continue
            for cipher in protocol['Ciphersuite']:
                ws.cell(row=row, column=1).value = i['IP']
                ws.cell(row=row, column=2).value = i['Hostname']
                ws.cell(row=row, column=3).value = int(i['Port'])
                ws.cell(row=row, column=4).value = i['LastDetected']
                ws.cell(row=row, column=5).value = protocol['Name']
                ws.cell(row=row, column=6).value = protocol['CompressionMethod']
                ws.cell(row=row, column=7).value = cipher['Name']
                ws.cell(row=row, column=8).value = cipher['KeyExchange']
                ws.cell(row=row, column=9).value = cipher['Authentication']
                ws.cell(row=row, column=10).value = cipher['MAC']
                ws.cell(row=row, column=11).value = cipher['Encryption']
                if cipher['KeyStrength'] == '':
                    ws.cell(row=row, column=12).value = cipher['KeyStrength']
                else:
                    ws.cell(row=row, column=12).value = int(cipher['KeyStrength'])
                ws.cell(row=row, column=13).value = cipher['Grade']
                row += 1

    wb.save(filename)
    print(f'{row-2} rows written to {filename}')


# Script entry point
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--username', help='API Username')
    parser.add_argument('--password', help='API Password')
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

    more_data = True
    print('Starting loop')
    url = f'{args.apiurl}/api/2.0/fo/asset/host/vm/detection?action=list&show_igs=1&qids=38116'
    full_inventory = []

    while more_data:
        print('Getting detection data')
        print(url)
        rcode, data = get_qualys_data(username=args.username, password=args.password, url=url)
        if rcode != 200:
            print('ERROR: Could not get Qualys detection data')
            exit(2)

        print('Building inventory')
        inventory, next_url = process_data(data)
        full_inventory += inventory

        if next_url is not None:
            url = next_url
        else:
            more_data = False

    print('Writing output file')
    output_inventory(inventory=full_inventory, filename=args.outputfile)
