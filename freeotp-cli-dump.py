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

import xml.etree.ElementTree as etree
import json
import pyotp

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


#import the freeotp xml backup file
#FIXME: Add getopts or ARGV
tree=etree.parse('tokens.xml')
tree_root=tree.getroot()

entities=dict()

#Parse json for the the site entries, remove the line that tell freeotp the order
for leaf in tree_root:
    values=json.loads(leaf.text)
    if leaf.attrib['name'] != 'tokenOrder':
        entities[leaf.attrib['name']]=values

for k,v in entities.items():
    decoded_secret = decode_secret( v['secret'] )
    token = pyotp.TOTP(decoded_secret).now()
    #FIXME:  Make this a flag so we are not exposeing the secret every time unless
    ## we really wnat to
    print( "%s , %s" % (k,decoded_secret) )
    #print( "%s,%s" % (k,token) )

