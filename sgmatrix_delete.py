##########################################################################################
## Trustsec Matrix SMC Policy Delete Tool
##
## This script will delete all Custom Security Events from Stealthwatch that have a 
## matching name to policies in the ISE TrustSec Matrix.
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
import base64
import time
import json
import requests
import query
import delete

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

    # Get all of the Custom Security Events from SWE
    eventsresponse = query.queryevents(config)
    eventsresponse = json.loads(json.dumps(eventsresponse))
    #print(json.dumps(eventsresponse, indent=4))

    # Perform searches through the captured JSON to print and DELETE from SWE
    print('======================================================================================')
    # Iterate through each Policy Egress Policy JSON
    for policy in egpolicyresponse['egressPolicies']:
        isepolicyname = policy["name"]
        smcevent_id = ""
        print("Looking for " + isepolicyname + " event in SMC Custom Security Events")
        for event in eventsresponse["customSecurityEvents"]:
            if event["name"] == isepolicyname:
                smcevent_id = event["id"]
                #print(smcevent_id)
        # Send event ID to delete.py for processing
        deleteresponse = delete.deleteevent(config, smcevent_id)
        if deleteresponse == 'DELETED':
            print("Event deleted successfully")
            print('======================================================================================')
        else:
            print("Policy has no matching Security Event")
            print('======================================================================================')
            continue