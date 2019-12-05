##########################################################################################
## Trustsec Matrix SMC Custom Security Event Policy Replication Tool
##
## This script will take all Trustsec matrix policies and build matching Custom Security
## events in Stealthwatch SMC.
## Script grabs Source and Destination Security Group Tags (SGTs) and associated SGACL
## If SGACL is only Deny IP statement only the script will create Custom Security Event to 
## alarm on any communication in either direction between SGTs.
## If SGACL contains Permit statements with a default "deny ip" the script will create a
## Custom Security Event that will alarm on all communication, excluding the permitted 
## ports and protocols.
## If SGACL contains Deny statements with a default "permit ip" the script will create a 
## Custom Security Event that will alarm only on communication that was denied between the
## two security groups in the SGACL.
## If SGACL is only Permit IP statement only the script will ignore and create no alarms.
##
## Notes: Supports single SGT assignment only. Multiple SGTs have not been tested.
##        Supports single destination port designation per SGACL line.
##########################################################################################
## System Requirements:
##    Stealthwatch Version: 7.0.0 or higher
##    Identity Services Engine: 2.3 or higher (pxGrid 2.0 Websocket)
##########################################################################################
## Author: Chad Mitchell
## License: BSD 3-Clause
## Version: 1.0
## Email: chadmi@cisco.com
##########################################################################################
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
## AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
## DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
## SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
## CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
## OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
## OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##########################################################################################

from pxgrid import PxgridControl
from config import Config
import urllib.request
import re
import base64
import time
import json
import requests
import query
import post

if __name__ == '__main__':
    config = Config()
    print(config)
    pxgrid = PxgridControl(config=config)

    while pxgrid.account_activate()['accountState'] != 'ENABLED':
        time.sleep(60)

    # ISE lookup for session service
    service_lookup_response = pxgrid.service_lookup('com.cisco.ise.config.trustsec')
    service = service_lookup_response['services'][0]
    node_name = service['nodeName']
    url = service['properties']['restBaseUrl']
    secret = pxgrid.get_access_secret(node_name)['secret']

    # Check config for SWE Tenant ID, if not present capture and add to config.json
    if config.get_swe_tenant() == "":
        tenantid = query.querytenants(config)
        #print(tenantid)

    # Get all of the Trustsec Egress Policies from ISE
    egpolicyresponse = query.queryegpolicy(config, secret, url, '{}')
    egpolicyresponse = json.loads(egpolicyresponse)
    #print(json.dumps(egpolicyresponse, indent=4))

    # Get all of the Security Groups from ISE
    sgroupresponse = query.querysgroups(config, secret, url, '{}')
    sgroupresponse = json.loads(sgroupresponse)
    #print(json.dumps(sgroupresponse, indent=4))

    # Get all of the SGACLs from ISE
    sgaclresponse = query.querysgacl(config, secret, url, '{}')
    sgaclresponse = json.loads(sgaclresponse)
    #print(json.dumps(sgaclresponse, indent=4))

    # Perform searches through the captured JSON to print and POST to SWE
    print('SG MATRIX POLICIES')
    print('============================================================================')
    # Iterate through each Policy Egress Policy JSON
    for policy in egpolicyresponse['egressPolicies']:
        # Search the Security Group JSON for matching Source & Destination Security Group ID
        for group in sgroupresponse["securityGroups"]:
            if group['id'] == policy['sourceSecurityGroupId']:
                sourcegroup = group['tag']
                #print(sourcegroup)
            if group['id'] == policy['destinationSecurityGroupId']:
                destgroup = group['tag']
                #print(destgroup)
        # Search the SGACL JSON for matching SGACLs assigned in Egress Policy
        for sgaclid in policy['sgaclIds']:
            for sgacl in sgaclresponse["securityGroupAcls"]:
                if sgacl['id'] == sgaclid:
                    sgaclvalue = sgacl['acl']
                    #print(sgaclvalue) 

        print('Policy: ' + policy['name'])
        print('Source: ' + str(sourcegroup))
        print('Destination: ' + str(destgroup))
        print('ACL Policy: \n' + sgaclvalue)
        name = policy["name"]
        try:
            desc = policy["description"]
        except KeyError:
            desc = policy["name"]
        srcsgt = sourcegroup
        dstsgt = destgroup
        includeportproto = []
        excludeportproto = []
        podomatch = re.search('((^deny ip(?=\ log|$))|(^permit ip$))', sgaclvalue)
        if podomatch != None:
            if podomatch.group(1) == "deny ip":
                print("Sending SGT Custom Event to Stealtwatch")
                request_data = post.createpayload(name, desc, srcsgt, dstsgt, excludeportproto, includeportproto)
                #print(json.dumps(request_data, indent=4)) 
                config_response = post.configevents(config, request_data)
                print(config_response)
            else:
                print('Permit Policy - Nothing to do here')
                print('============================================================================')
                continue
        denyipmatch = re.search('\\ndeny ip$', sgaclvalue)
        if denyipmatch != None:
            poptrex = r"permit\ (?P<protocol>\w+)(?=\ dst\ (?P<port>\d+))?"
            poptlist = []
            for match in re.finditer(poptrex, sgaclvalue):
                if match.group('port') != None:
                    portproto = match.group('port') + '/' + match.group('protocol')
                    poptlist.append(portproto)
                else:
                    proto = match.group('protocol')
                    poptlist.append(proto)
            #print(poptlist)
            print("Sending SGT Custom Event to Stealtwatch")
            excludeportproto = poptlist
            request_data = post.createpayload(name, desc, srcsgt, dstsgt, excludeportproto, includeportproto)
            #print(json.dumps(request_data, indent=4))
            config_response = post.configevents(config, request_data)
            print(config_response) 
        permitipmatch = re.search('\\npermit ip$', sgaclvalue)
        if permitipmatch != None:
            poptrex = r"deny\ (?P<protocol>\w+)(?=\ dst\ (?P<port>\d+))?"
            poptlist = []
            for match in re.finditer(poptrex, sgaclvalue):
                if match.group('port') != None:
                    portproto = match.group('port') + '/' + match.group('protocol')
                    poptlist.append(portproto)
                else:
                    proto = match.group('protocol')
                    poptlist.append(proto)
            #print(poptlist)
            print("Sending SGT Custom Event to Stealtwatch")
            includeportproto = poptlist
            request_data = post.createpayload(name, desc, srcsgt, dstsgt, excludeportproto, includeportproto)
            #print(json.dumps(request_data, indent=4))
            config_response = post.configevents(config, request_data)
            print(config_response)
        print('============================================================================')