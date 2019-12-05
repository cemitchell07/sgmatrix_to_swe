# Identity Services Engine Trustsec Matrix to Stealthwatch Enterprise Policy Sync Tool
This repository contains scripts to synchronize ISE Trustsec policy with Stealthwatch Custom Security Events. It is available for use by anyone who wants Trustsec policy monitoring policies to be built dynamically into Stealthwatch Custom Security Events

## Compatibility
The minimum supported version of Stealthwatch Enterprise that is required to use each respective API capability:
   * Stealhwatch Enterprise v7.0.0 or greater
   * Identity Services Engine v2.3 or greater

## Installation
1. Ensure pxGrid is enabled on ISE.
   * For details see: https://developer.cisco.com/docs/pxgrid/#!configuring-ise-for-pxgrid
2. Ensure DNS for ISE pxGrid nodes, Stealthwatch SMCs, and host running scripts is up to date.
3. Generate pxGrid Client certificates using ISE Certificate Services or enterprise CA server. See: https://developer.cisco.com/docs/pxgrid/#!generating-certificates/generating-certificates
4. Generate account for REST API calls on Stealthwatch Enterprise.
5. Ensure Python 3.6 or greater is installed on system running scripts

## Configuration
1. Upload and install certificates from ISE to the "certs" directory.
2. Update config.json with pxGrid and Stealthwatch credentials
3. Please set the following fields appropriately:
    * `PXGRID_HOST` Hostname of ISE pxGrid node
    * `PXGRID_NAME` Friendly name of Replication Tool host
    * `PXGRID_DESC` (optional) Description of pxGrid host
    * `PASSWORD` (optional) Pre-Shared Key Password if not using Certificate Authentication to pxGrid
    * `PXGRID_CLIENTCERT` Location of Replication Tool client certificate from CA
    * `PXGRID_CLIENTKEY` Location of Replication Tool client certificate key
    * `PXGRID_KEYPASS` Client certificate private key password
    * `PXGRID_CACERT` Certificate of certificate chain for CA that signed ISE pxGrid certificate
    * `SMC_HOST` Hostname or IP of Stealthwatch Management Console (SMC)
    * `SMC_USER` SMC REST API Username
    * `SMC_PASSWORD` SMC REST API User password 
    * `SMC_TENANT_ID` (optional) SMC Tenant ID

## Usage
1. Run manually via replication tool cli using "python3.6 sgmatrix_to_swe.py" of via CRON job on a scheduled basis.

## Limitations
Supports single SGT assignment only. Multiple SGTs have not been tested.
Supports single destination port designation per SGACL line.

## Getting help
Use this project at your own risk (support not provided). *If you need technical support with Cisco ISE pxGrid or Stealthwatch APIs, do the following:*

#### Open A Case
* To open a case by web: http://www.cisco.com/c/en/us/support/index.html
* To open a case by email: tac@cisco.com
* For phone support: 1-800-553-2447 (U.S.)
* For worldwide support numbers: www.cisco.com/en/US/partner/support/tsd_cisco_worldwide_contacts.html

## Licensing info
This code is licensed under the BSD 3-Clause License. See [LICENSE](./LICENSE) for details. 

