##########################################################################################
## Post Functions for Identity Services Engine and Stealthwatch SMC
##
## This script contains all functions used to post to  ISE and SMC for sgmatrix_to_swe.py 
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

import json
import requests

# Function to create the request_data JSON payload for SMC
def createpayload(name, desc, srcsgt, dstsgt, excludeportproto, includeportproto):
    data = {
            'name': name,
            'description': desc,
            'subject': {
                'orientation': 'either',
                'trustSecIds': {
                    'includes': [srcsgt],
                    "excludes": []
                }
            },
            'peer': {
                'trustSecIds': {
                    'includes': [dstsgt],
                    'excludes': []
                },
                "portProtocols": {
                    "excludes": excludeportproto,
                    "includes": includeportproto
                },
            },
        }
    return data

# Function to create Custom Security Events in SMC
def configevents(config, request_data):
    try:
        requests.packages.urllib3.disable_warnings()
    except:
        pass
    url = "https://" + config.get_swe_host() + "/token/v2/authenticate"
    # Create the login request data
    login_request_data = {"username": config.get_swe_user(), "password": config.get_swe_pass()}
    # Initialize the Requests session
    api_session = requests.Session()
    # Perform the POST request to login
    response = api_session.request("POST", url, verify=False, data=login_request_data)
    # If the login was successful
    if(response.status_code == 200):
        # Add the new event
        url = 'https://' + config.get_swe_host() + '/smc-configuration/rest/v1/tenants/' + config.get_swe_tenant() + '/policy/customEvents'
        request_headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
        response = api_session.request("POST", url, verify=False, data=json.dumps(request_data), headers=request_headers)
        # If successful grab the event ID from the response and enable the event
        if (response.status_code == 200):
            custom_event = json.loads(response.content)["data"]
            event_id = custom_event["customSecurityEvents"]["id"]
            # Enable the event
            url = 'https://' + config.get_swe_host() + '/smc-configuration/rest/v1/tenants/' + config.get_swe_tenant() + '/policy/customEvents/' + str(event_id) + '/enable'
            timestamp = custom_event["customSecurityEvents"]["timestamp"]
            request_data = {'timestamp': timestamp}
            response = api_session.request("PUT", url, verify=False, data=json.dumps(request_data), headers=request_headers)
            return_response = "New event (id:{}) successfully created and enabled".format(event_id)

        # If unable to add the event
        else:
            errormessage = json.loads(response.content)["errors"][1]
            sweerrorcode = json.loads(response.content)["errors"][0]["code"]
            # If the event name already exists or is "stale" perform event update
            print("{}. Attempting update.".format(errormessage))
            if sweerrorcode == 5060:
                # Have to query all events from SMC to match name and grab event ID to update
                url = 'https://' + config.get_swe_host() + '/smc-configuration/rest/v1/tenants/' + config.get_swe_tenant() + '/policy/customEvents'
                response = api_session.request("GET", url, verify=False)
                if (response.status_code == 200):
                    event_list = json.loads(response.content)["data"]
                    request = json.loads(json.dumps(request_data))
                    for event in event_list["customSecurityEvents"]:
                        if event["name"] == request["name"]:
                            url = 'https://' + config.get_swe_host() + '/smc-configuration/rest/v1/tenants/' + config.get_swe_tenant() + '/policy/customEvents/' + str(event["id"]) + '?force=true'
                            response = api_session.request("PUT", url, verify=False, data=json.dumps(request_data), headers=request_headers)
                            if (response.status_code == 200):
                                return_response = "Existing event (id:{}) successfully updated".format(event["id"])
                            else:
                                errormessage = json.loads(response.content)["errors"][1]
                                sweerrorcode = json.loads(response.content)["errors"][0]["code"]
                                return_response = "Error {} : {}".format(sweerrorcode, errormessage)
        uri = 'https://' + config.get_swe_host() + '/token'
        deleteresponse = api_session.delete(uri, timeout=30, verify=False)

    # If the login was unsuccessful
    else:
            print("An error has ocurred, while logging in, with the following code {}".format(response.status_code))
    return return_response
