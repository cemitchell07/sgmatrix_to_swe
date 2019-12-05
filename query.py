##########################################################################################
## Query Functions for Identity Services Engine and Stealthwatch SMC
##
## This script contains all functions used to query ISE and SMC for sgmatrix_to_swe.py 
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

import urllib.request
import base64
import time
import json
import requests

# Function to build the request variables to query ISE
def buildrestrequest(config, secret, url, payload):
    rest_request = urllib.request.Request(url=url, data=str.encode(payload))
    rest_request.add_header('Content-Type', 'application/json')
    rest_request.add_header('Accept', 'application/json')
    b64 = base64.b64encode((config.get_node_name() + ':' + secret).encode()).decode()
    rest_request.add_header('Authorization', 'Basic ' + b64)
    return rest_request

# Function to get Egress Policies / Trustsec Matrix from ISE
def queryegpolicy(config, secret, url, payload):
    url = url + '/getEgressPolicies'
    handler = urllib.request.HTTPSHandler(context=config.get_ssl_context())
    opener = urllib.request.build_opener(handler)
    rest_request = buildrestrequest(config, secret, url, payload)
    rest_response = opener.open(rest_request)
    egpolicyresponse = rest_response.read().decode()
    return egpolicyresponse

# Function to get all Trustsec Security Groups from ISE
def querysgroups(config, secret, url, payload):
    url = url + '/getSecurityGroups'
    handler = urllib.request.HTTPSHandler(context=config.get_ssl_context())
    opener = urllib.request.build_opener(handler)
    rest_request = buildrestrequest(config, secret, url, payload)
    rest_response = opener.open(rest_request)
    sgroupresponse = rest_response.read().decode()
    return sgroupresponse

# Function to get all SGACLs from ISE
def querysgacl(config, secret, url, payload):
    url = url + '/getSecurityGroupAcls'
    handler = urllib.request.HTTPSHandler(context=config.get_ssl_context())
    opener = urllib.request.build_opener(handler)
    rest_request = buildrestrequest(config, secret, url, payload)
    rest_response = opener.open(rest_request)
    sgaclresponse = rest_response.read().decode()
    return sgaclresponse

# Function to get Tenant ID from SMC
def querytenants(config):
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
        # Get the list of tenants (domains) from the SMC
        url = 'https://' + config.get_swe_host() + '/sw-reporting/v1/tenants/'
        response = api_session.request("GET", url, verify=False)
        # If successfully able to get list of tenants (domains)
        if (response.status_code == 200):
            # Store the tenant (domain) ID as a variable to use later
            tenant_list = json.loads(response.content)["data"]
            tenantid = tenant_list[0]["id"]
            #print("Tenant ID = {}".format(tenantid))
            jsonconfig = json.loads(open("config.json").read())
            jsonconfig["SMC_TENANT_ID"] = "{}".format(tenantid)
            with open ("config.json", "w") as outfile:
                json.dump(jsonconfig, outfile, indent=4)
        # If unable to fetch list of tenants (domains)
        else:
            print("An error has ocurred, while fetching tenants (domains), with the following code {}".format(response.status_code))
        uri = 'https://' + config.get_swe_host() + '/token'
        response = api_session.delete(uri, timeout=30, verify=False)
    # If the login was unsuccessful
    else:
        print("An error has ocurred, while logging in, with the following code {}".format(response.status_code))
    return tenantid

# Function to get all Custom Security Events from SMC
def queryevents(config):
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
        # Get the list of Custom Security Events from the SMC
        url = 'https://' + config.get_swe_host() + '/smc-configuration/rest/v1/tenants/' + config.get_swe_tenant() + '/policy/customEvents'
        response = api_session.request("GET", url, verify=False)
        # If successfully able to get list events
        if (response.status_code == 200):
            # Store the event list as JSON to use later
            events_list = json.loads(response.content)["data"]
        # If unable to fetch list events
        else:
            print("An error has ocurred, while fetching events, with the following code {}".format(response.status_code))
        uri = 'https://' + config.get_swe_host() + '/token'
        response = api_session.delete(uri, timeout=30, verify=False)
    # If the login was unsuccessful
    else:
        print("An error has ocurred, while logging in, with the following code {}".format(response.status_code))
    return events_list
