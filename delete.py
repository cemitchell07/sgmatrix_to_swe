##########################################################################################
## Delete Functions for Identity Services Engine and Stealthwatch SMC
##
## This script contains all functions used to delete events from SMC for 
## sgmatrix_to_swe.py 
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

def deleteevent(config, event_id):
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
        # Delete the event from the the SMC
        url = 'https://' + config.get_swe_host() + '/smc-configuration/rest/v1/tenants/' + config.get_swe_tenant() + '/policy/customEvents/' + str(event_id)
        response = api_session.request("DELETE", url, verify=False)
        # If successfully
        if (response.status_code == 200):
            # If successful return response
            deleteresponse = "DELETED"
        # If unable to delete
        else:
            deleteresponse = "FAILED"
        uri = 'https://' + config.get_swe_host() + '/token'
        response = api_session.delete(uri, timeout=30, verify=False)
    # If the login was unsuccessful
    else:
        print("An error has ocurred, while logging in, with the following code {}".format(response.status_code))
    return deleteresponse
