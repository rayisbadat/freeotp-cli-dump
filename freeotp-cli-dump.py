# Author: Ray Powell <ray@xphoniexx.net>
##
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import xml.etree.ElementTree as etree
import json
import pyotp
import pyqrcode
from pprint import pprint
from argparse import ArgumentParser

DEFAULT_XML_FILE = 'tokens.xml'

def parse_cmd_args():
    """ Routine to setup & use argparse for command line args """
    parser = ArgumentParser()

    parser.add_argument('-f', '--xml_file',
                        help=f"xml file with creds, default: {DEFAULT_XML_FILE}",
                        default=DEFAULT_XML_FILE)
    parser.add_argument('-q', '--show_qr_codes',
                        help='display text qr codes',
                        action='store_true')
    parser.add_argument('-v', '--save_qr_code_images',
                        help='save QR codes to image files',
                        action='store_true')
    parser.add_argument('-l', '--list_entries',
                        help='list entries without showing any secrets',
                        action='store_true')
    parser.add_argument('-s', '--secrets',
                        help='list of secrets to process, '
                        'checking each key value in the XML '
                        'matching if any part of the given string matches. '
                        'Strings are case sensitive. '
                        'Format: "-s google reddit" ',
                        nargs='+')

    args = parser.parse_args()
    return args


def decode_secret(secret):
    """
        decodes the array of signed ints back into the base32secret using bit shifts
        Function ported from the work by philipsharp https://github.com/philipsharp/FreeOTPDecoder/blob/master/decoder.php
    """

    CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' #Valid Characters
    SHIFT = 5 # Unit to bitshift by
    MASK = len(CHARS) - 1 
    bits_left = 8 
    secret_decoded = ""

    #Load in the first signed short int
    snext = 0 
    sbuffer = secret[snext]
    snext += 1

    #while their are unprocessed bits, or the index 
    ##hasnt reached last signed int in secret list
    while (bits_left > 0) or (snext < len(secret)):
        if (bits_left < SHIFT ):
            # if ints left in secret, then shift it into list
            if snext < len(secret):
                sbuffer <<= 8
                sbuffer |= ( secret[snext] & 0xff )
                snext += 1
                bits_left += 8
            #Not entitely sure yet
            #But if we dont have a full SHIFT=5 bits, pad them out?
            else:
                pad = SHIFT - bits_left
                sbuffer <<= pad
                bits_left += pad
        #Generate an index into the array of valid characters
        index = MASK & (sbuffer >> (bits_left - SHIFT))
        #Deduct SHIFT from availble bits, for above if statement
        bits_left -= SHIFT
        #Find the next character in the secret, add to string
        secret_decoded += CHARS[index]

    return secret_decoded

def print_QRcode(string, tag=None, save_image=False):
    url = pyqrcode.create(string)
    print( string )
    print(url.terminal(quiet_zone=1))
    print( "\n-----\n" )
    if save_image:
        qr_code_file_name = f"{tag.replace(':','-')}.png"
        try:
            url.png(qr_code_file_name,
                    scale=8,
                    module_color=[0, 0, 0, 255], 
                    background=[0xff, 0xff, 0xff])
        except Exception as exception:
            print(f"Unable to save {qr_code_file_name}: {exception}")

def main():
    args = parse_cmd_args()

    if os.path.isfile(args.xml_file):
        #import the freeotp xml backup file
        tree=etree.parse(args.xml_file)
        tree_root=tree.getroot()

        entities=dict()

        #Parse json for the the site entries, remove the line 
        # that tells freeotp the order
        for leaf in tree_root:
            values=json.loads(leaf.text)
            if leaf.attrib['name'] != 'tokenOrder':
                entities[leaf.attrib['name']]=values

        processed = 0
        for k,v in entities.items():
            if args.secrets:
                secret_found = False
                for arg_secret in args.secrets:
                    if arg_secret in k:
                        secret_found = True
                        break
                if not secret_found:
                    continue
            processed += 1
            decoded_secret = decode_secret( v['secret'] )
            token = pyotp.TOTP(decoded_secret).now()
            if not args.list_entries:
                print(f"{k} , {decoded_secret}")
                #print( "%s,%s" % (k,token) )
                
                # This will generate the uri and send to 
                # print a QR code for scanning
                totp = pyotp.TOTP(decoded_secret)
                provisioning_uri=totp.provisioning_uri(k)
                if args.show_qr_codes:
                    print_QRcode(
                        provisioning_uri,
                        tag=k, save_image=args.save_qr_code_images)
            else:
                print(f"{k}")
        
        print(f"{len(entities)} total secrets found, {processed} processed")

    else:
        print(f"Unable to find {args.xml_file}, please verify location")

if __name__ == "__main__":
    main()
