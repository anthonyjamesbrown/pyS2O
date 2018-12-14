import os
import string
import json
import requests
import secrets
import jinja2
import base64

CERT_PATH = r'.\certs\curl-ca-bundle.crt'

##################################################
# Functions
##################################################

# 'Get' Functions - Get data from PF Admin API
##################################################
def get_pf_access_token_manager(server_name, username, password, clientid):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/oauth/accessTokenManagers'
    headers = {'X-XSRF-Header': 'PingFederate'}

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    item = [atm for atm in json_response['items'] if atm['name'] == clientid]
 
    if len(item) < 1:
        return None
    elif len(item) == 1:
        results = item[0]
    else:
        item.sort(key=lambda x: x['name'])
        results = item[0]

    return results

def get_pf_access_token_manager_list(server_name, username, password):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/oauth/accessTokenManagers'
    headers = {'X-XSRF-Header': 'PingFederate'}

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    results = json_response['items']

    return results

def get_pf_access_token_manager_mapping(server_name, username, password, clientid):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/oauth/accessTokenMappings'
    headers = {'X-XSRF-Header': 'PingFederate'}

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    id = 'authz_req|IWA|' + clientid
    item = [atmap for atmap in json_response if atmap['id'] == id]
 
    if len(item) < 1:
        return None
    elif len(item) == 1:
        results = item[0]
    else:
        item.sort(key=lambda x: x['id'])
        results = item[0]

    return results

def get_pf_access_token_manager_mapping_list(server_name, username, password):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/oauth/accessTokenMappings'
    headers = {'X-XSRF-Header': 'PingFederate'}

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    results = json_response

    return results

def get_pf_authentication_policy_contracts(server_name, username, password):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + 'authenticationPolicyContracts'
    headers = {'X-XSRF-Header': 'PingFederate'}

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    results = json_response['items']
    
    return results

def get_pf_cluster_status(server_name, username, password):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/cluster/status'
    headers = {'X-XSRF-Header': 'PingFederate'}

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    results = json_response

    return results

def get_pf_data_store(server_name, username, password, id=0):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/dataStores'
    headers = {'X-XSRF-Header': 'PingFederate'}

    if id != 0:
        uri += '/' + id

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    
    if id == 0:
        results = json_response['items']
    else:
        results = json_response

    return results

def get_pf_idp_adapter(server_name, username, password, id=0):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/idp/adapters'
    headers = {'X-XSRF-Header': 'PingFederate'}

    if id != 0:
        uri += '/' + id

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    
    if id == 0:
        results = json_response['items']
    else:
        results = json_response

    return results

def get_pf_idp_adapter_descriptor(server_name, username, password):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/idp/adapters/descriptors'
    headers = {'X-XSRF-Header': 'PingFederate'}

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    results = json_response['items']
    
    return results

def get_pf_kerberos_realm(server_name, username, password, id=0):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/kerberos/realms'
    headers = {'X-XSRF-Header': 'PingFederate'}

    if id != 0:
        uri += '/' + id

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    
    if id == 0:
        results = json_response['items']
    else:
        results = json_response

    return results

def get_pf_kerberos_realm_setting(server_name, username, password):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/kerberos/realms/settings'
    headers = {'X-XSRF-Header': 'PingFederate'}

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    results = json_response

    return results

def get_pf_oauth_client(server_name, username, password, clientid):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/oauth/clients'
    headers = {'X-XSRF-Header': 'PingFederate'}

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    item = [oauth for oauth in json_response['items'] if oauth['clientId'] == clientid]
 
    if len(item) < 1:
        return None
    elif len(item) == 1:
        results = item[0]
    else:
        item.sort(key=lambda x: x['clientId'])
        results = item[0]

    return results

def get_pf_oauth_client_list(server_name, username, password):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/oauth/clients'
    headers = {'X-XSRF-Header': 'PingFederate'}

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    results = json_response['items']

    return results

def get_pf_oauth_token(server_name, username, password):

    return 0

def get_pf_openid_connect_policy(server_name, username, password, id=0):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/oauth/openIdConnect/policies'
    headers = {'X-XSRF-Header': 'PingFederate'}

    if id != 0:
        uri += '/' + id

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    
    if id == 0:
        results = json_response['items']
    else:
        results = json_response

    return results

def get_pf_password_credential_validator(server_name, username, password, id=0):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/passwordCredentialValidators'
    headers = {'X-XSRF-Header': 'PingFederate'}

    if id != 0:
        uri += '/' + id

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    
    if id == 0:
        results = json_response['items']
    else:
        results = json_response

    return results

def get_pf_signing_keypair(server_name, username, password, subject_dn, item_property):

    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/keyPairs/signing'
    headers = {'X-XSRF-Header': 'PingFederate'}

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    item = [cert for cert in json_response['items'] if cert['subjectDN'] == subject_dn]

    if len(item) < 1:
        return None
    elif len(item) == 1:
        results = item[0]
    else:
        item.sort(key=lambda x: x['expires'], reverse=True)
        results = item[0]

    new_item = {x: results[x] for x in item_property if x in results}

    return new_item

def get_pf_sp_connection(server_name, username, password, id=0):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/idp/spConnections'
    headers = {'X-XSRF-Header': 'PingFederate'}

    if id != 0:
        uri += '/' + id

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    
    if id == 0:
        results = json_response['items']
    else:
        results = json_response

    return results

def get_pf_version(server_name, username, password):

    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/version'
    headers = {'X-XSRF-Header': 'PingFederate'}

    r = requests.get(uri, auth=(username, password), verify=CERT_PATH, headers=headers)
    json_response = r.json()
    version = json_response['version']
    return version

# Config Generator Functions - Use templates and Jinja2 to generate JSON SSO configs
##################################################
def generate_config_pf_oauth_client(
        clientid,
        grant_type,
        client_secret='',
        redirect_uris=['http://localhost/login','http://ucsinfo.int.company.com/'],
        restricted_scopes=['email', 'openid', 'profile']):
    from jinja2 import Environment, PackageLoader, select_autoescape
    env = Environment(
        loader=PackageLoader('SSOFunctions', '.\\templates'),
        autoescape=select_autoescape(['html', 'xml'])
    )

    template = env.get_template('Template_Client.jinja2')

    client_dict = {
        'pfClientId':clientid,
        'pfGrantType':grant_type,
        'pfClientSecret':client_secret,
        'pfRedirectURIs':redirect_uris,
        'pfRestrictedScopes':restricted_scopes
    }

    config = template.render(client_dict)

    return config

def generate_config_pf_oidc_policy(
        clientid,
        vds_datastore_id,
        include_groups=True,
        restrict_ip_internal=False,
        restrict_to_group=False,
        restricted_group=''):
    from jinja2 import Environment, PackageLoader, select_autoescape
    env = Environment(
        loader=PackageLoader('SSOFunctions', '.\\templates'),
        autoescape=select_autoescape(['html', 'xml'])
    )

    template = env.get_template('Template_OIDCPolicy.jinja2')
    
    oidc_dict = {
        'pfClientId':clientid,
        'pfVDSDataStoreId':vds_datastore_id,
        'pfIncludeGroups':include_groups,
        'pfRestrictIPInternal':restrict_ip_internal,
        'pfRestrictToGroup':restrict_to_group,
        'pfRestrictedGroup':restricted_group
    }

    config = template.render(oidc_dict)
    return config

def generate_config_pf_access_token_manager_initial(
        clientid,
        ssokeyid,
        atm_parent_id):
    from jinja2 import Environment, PackageLoader, select_autoescape
    env = Environment(
        loader=PackageLoader('SSOFunctions', '.\\templates'),
        autoescape=select_autoescape(['html', 'xml'])
    )

    template = env.get_template('Template_AccessTokenManager_Inherit_Create.jinja2')

    atm_dict = {
        'pfClientId':clientid,
        'pfAccessTokenManagerParentId':atm_parent_id,
        'pfssokeyid':ssokeyid,
    }
    
    config = template.render(atm_dict)
    return config

def generate_config_pf_access_token_manager_update(
        clientid,
        ssokeyid,
        atm_parent_id,
        set_jwks_path=False):
    from jinja2 import Environment, PackageLoader, select_autoescape
    env = Environment(
        loader=PackageLoader('SSOFunctions', '.\\templates'),
        autoescape=select_autoescape(['html', 'xml'])
    )

    template = env.get_template('Template_AccessTokenManager_Inherit_Update.jinja2')

    atm_dict = {
        'pfClientId':clientid,
        'pfAccessTokenManagerParentId':atm_parent_id,
        'pfssokeyid':ssokeyid,
        'pfSetJWKSPath':set_jwks_path
    }

    config = template.render(atm_dict)
    return config

def generate_config_pf_access_token_mapping(clientid, datastore_id, user_key_attribute):
    from jinja2 import Environment, PackageLoader, select_autoescape
    env = Environment(
        loader=PackageLoader('SSOFunctions', '.\\templates'),
        autoescape=select_autoescape(['html', 'xml'])
    )

    template = env.get_template('Template_AccessTokenMapping_IWA_Create.jinja2')

    atmap_dict = {
        'pfClientId':clientid,
        'pfDataStoreId':datastore_id,
        'pfUserKeyAttribute':user_key_attribute
    }

    config = template.render(atmap_dict)

    return config

# 'Invoke' and 'Import' Fuctions - Misc
##################################################
def import_pf_signing_keypair(server_name, username, password, path, cert_password):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/keyPairs/signing/import'
    headers = {'X-XSRF-Header': 'PingFederate', 'content-type': 'application/json'}

    with open(path) as f:
        encoded = base64.b64encode(f.read())
    
    data = {}
    data['fileData'] = encoded
    data['password'] = cert_password
    body = json.dumps(data)

    r = requests.post(uri, auth=(username, password), verify=CERT_PATH, headers=headers, json=body)

    status_code = r.status_code
    r.raise_for_status()

    return status_code

def invoke_pf_cluster_replication(server_name, username, password):
    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/cluster/replicate'
    headers = {'X-XSRF-Header': 'PingFederate', 'content-type': 'application/json'}

    r = requests.post(uri, auth=(username, password), verify=CERT_PATH, headers=headers)

    status_code = r.status_code
    r.raise_for_status()

    return status_code

# 'Set' Functions - Post data to the PF Admin API
##################################################
def set_pf_access_token_manager(server_name, username, password, config, action='update'):
    if action in ('create', 'update'):
        admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
        uri = admin_uri + '/oauth/accessTokenManagers'
        headers = {'X-XSRF-Header': 'PingFederate', 'content-type': 'application/json'}

        body = json.loads(config)
        clientid = body['id']

        if action == 'create':
            r = requests.post(
                uri,
                auth=(username, password),
                verify=CERT_PATH,
                headers=headers,
                json=body)
        elif action == 'update':
            update_uri = uri + '/' + clientid
            r = requests.put(
                update_uri,
                auth=(username, password),
                verify=CERT_PATH,
                headers=headers,
                json=body)
        
        status_code = r.status_code
        r.raise_for_status()

        return status_code
    else:
        return ("Error: The value passed for the action parameter in not recognized. "
                + "Only 'create' or 'update' is allowed.")

def set_pf_oidc_policy(server_name, username, password, config, action='update'):
    if action in ('create', 'update'):
        admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
        uri = admin_uri + '/oauth/openIdConnect/policies'
        headers = {'X-XSRF-Header': 'PingFederate', 'content-type': 'application/json'}

        body = json.loads(config)
        clientid = body['id']

        if action == 'create':
            r = requests.post(
                uri,
                auth=(username, password),
                verify=CERT_PATH,
                headers=headers,
                json=body)
        elif action == 'update':
            update_uri = uri + '/' + clientid
            r = requests.put(
                update_uri,
                auth=(username, password),
                verify=CERT_PATH,
                headers=headers,
                json=body)

        status_code = r.status_code
        r.raise_for_status()

        return status_code
    else:
        return ("The value passed for the action parameter in not recognized. "
                + "Only 'create' or 'update' is allowed.")

def set_pf_oauth_client(server_name, username, password, config, action='update'):
    if action in ('create', 'update'):
        admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
        uri = admin_uri + '/oauth/clients'
        headers = {'X-XSRF-Header': 'PingFederate', 'content-type': 'application/json'}

        body = json.loads(config)
        clientid = body['clientId']

        if action == 'create':
            r = requests.post(
                uri,
                auth=(username, password),
                verify=CERT_PATH,
                headers=headers,
                json=body)
        elif action == 'update':
            update_uri = uri + '/' + clientid
            r = requests.put(
                update_uri,
                auth=(username, password),
                verify=CERT_PATH,
                headers=headers,
                json=body)

        status_code = r.status_code
        r.raise_for_status()

        return status_code
    else:
        return ("The value passed for the action parameter in not recognized. "
                + "Only 'create' or 'update' is allowed.")

# New Functions - Functions that leverage other functions to create new items in PF Admin API
##################################################
def new_pf_access_token_manager(server_name, username, password, clientid):

    subject_dn = 'CN=ndcsso.company.com, O=company, L=Nashville, ST=Tennessee, C=US'
    pf_signing_key = get_pf_signing_keypair(
        server_name,
        username,
        password,
        subject_dn,
        item_property=('id', 'expires'))
    ssokeyid = pf_signing_key['id']
    config = generate_config_pf_access_token_manager_initial(
        clientid,
        ssokeyid,
        atm_parent_id='UPN')

    response = set_pf_access_token_manager(
        server_name,
        username,
        password,
        config,
        action='create')

    return response

def new_pf_oidc_policy(
        server_name,
        username,
        password,
        clientid,
        include_groups=True,
        restrict_ip_internal=False,
        restrict_to_group=False,
        restricted_group=''):

    vds_data_store_id = 'LDAP-936318AB4893E9702AA1ED209BAF069171BBDAEE'

    oidc_dict = {
        'clientid':clientid,
        'vds_datastore_id':vds_data_store_id,
        'include_groups':include_groups,
        'restrict_ip_internal':restrict_ip_internal,
        'restrict_to_group':restrict_to_group,
        'restricted_group':restricted_group
    }

    config = generate_config_pf_oidc_policy(**oidc_dict)

    response = set_pf_oidc_policy(server_name, username, password, config, action='create')

    return response

def new_pf_oauth_client(
        server_name,
        username,
        password,
        clientid,
        grant_type,
        client_secret='',
        redirect_uris=['http://localhost/login','http://ucsinfo.int.company.com/'],
        restricted_scopes=['email', 'openid', 'profile']):

    client_dict = {
        'clientid':clientid,
        'grant_type':grant_type,
        'client_secret':client_secret,
        'redirect_uris':redirect_uris,
        'restricted_scopes':restricted_scopes
    }

    config = generate_config_pf_oauth_client(**client_dict)

    response = set_pf_oauth_client(server_name, username, password, config, action='create')

    return response

def new_pf_access_token_manager_mapping(
        server_name,
        username,
        password,
        clientid,
        user_key_attribute='userPrincipalName'):

    vds_data_store_id = 'LDAP-936318AB4893E9702AA1ED209BAF069171BBDAEE'

    admin_uri = 'https://' + server_name + ':9999/pf-admin-api/v1'
    uri = admin_uri + '/oauth/accessTokenMappings'
    headers = {'X-XSRF-Header': 'PingFederate', 'content-type': 'application/json'}

    atm_id = get_pf_access_token_manager(server_name, username, password, clientid)

    if atm_id != None:
        id = atm_id['id']
        if clientid == id:
            data_store_data = get_pf_data_store(
                server_name,
                username,
                password,
                vds_data_store_id)
            data_store_id = data_store_data['id']
            if vds_data_store_id == data_store_id:
                config = generate_config_pf_access_token_mapping(
                    clientid,
                    data_store_id,
                    user_key_attribute)

                body = json.loads(config)

                r = requests.post(
                    uri,
                    auth=(username, password),
                    verify=CERT_PATH,
                    headers=headers,
                    json=body)

                status_code = r.status_code
                r.raise_for_status()

                return status_code
            else:
                return ("Error: Couldn't retrieve the data store id with 'VDS Data Store id' :"
                        + vds_data_store_id + "from computer: " + server_name)
        else:
            return ('Error: The clientid: ' + clientid + ' and atm id: ' + id
                    + ' did not match.  Make sure a access token manager has been created.')
    else:
        return 'Error: A access token manager entry could not be found for clientid: ' + clientid

    return 0

def new_pf_oidc_connection(
        server_name,
        username,
        password,
        clientid,
        grant_type,
        redirect_uris=['http://localhost/login','http://ucsinfo.int.company.com/'],
        restricted_scopes=['email', 'openid', 'profile'],
        include_groups=True,
        restrict_ip_internal=False,
        restrict_to_group=False,
        restricted_group='',
        atm_parent_id='UPN',
        set_jwks_path=False):

    if grant_type.upper() == 'AUTHORIZATION_CODE':
        client_secret = new_pf_client_secret()
    else:
        client_secret = ''

    subject_dn = 'CN=ndcsso.company.com, O=company, L=Nashville, ST=Tennessee, C=US'
    pf_signing_key = get_pf_signing_keypair(
        server_name,
        username,
        password,
        subject_dn,
        item_property=('id', 'expires'))
    ssokeyid = pf_signing_key['id']

    atm_result = new_pf_access_token_manager(server_name, username, password, clientid)

    if atm_result == 201:
        atmap_result = new_pf_access_token_manager_mapping(
            server_name,
            username,
            password,
            clientid)
        if atmap_result == 201:
            oidc_policy_result = new_pf_oidc_policy(
                server_name,
                username,
                password,
                clientid,
                include_groups,
                restrict_ip_internal,
                restrict_to_group,
                restricted_group)
            if oidc_policy_result == 201:
                oauth_client_result = new_pf_oauth_client(
                    server_name,
                    username,
                    password,
                    clientid,
                    grant_type,
                    client_secret,
                    redirect_uris,
                    restricted_scopes)
                if oauth_client_result == 201:
                    config = generate_config_pf_access_token_manager_update(
                        clientid,
                        ssokeyid,
                        atm_parent_id,
                        set_jwks_path)
                    update_atm_result = set_pf_access_token_manager(
                        server_name,
                        username,
                        password,
                        config,
                        action='update')
                    if update_atm_result == 200 or update_atm_result == 201:
                        replication_result = invoke_pf_cluster_replication(
                            server_name,
                            username,
                            password)
                        if replication_result == 200:
                            return {'status': 'success', 'client_secret': client_secret}
                        else:
                            return {'status': 'replication request failed',
                                    'client_secret': client_secret}
                    else:
                        {'status': 'atm update failed', 'client_secret': client_secret}
                else:
                    {'status': 'create oauth client failed', 'client_secret': client_secret}
            else:
                {'status': 'create oidc policy faild', 'client_secret': client_secret}
        else:
            {'status': 'create atm mapping failed', 'client_secret': client_secret}
    else:
        {'status': 'create atm failed', 'client_secret': client_secret}

    return 0

def new_pf_client_secret():
    alphabet = string.ascii_letters + string.digits
    client_secret = ''.join(secrets.choice(alphabet) for i in range(64))
    return client_secret

################### MAIN ###############################
def main():

    server_name = 'ndcssodev1'

    username = os.environ.get('PFUSER')
    password = os.environ.get('PFPW')

    if not username and not password:
        print('WARNING: You need to set PFUSER and PFPW credentials as ENV variables')

    print(get_pf_version(server_name, username, password))

if __name__ == '__main__':
    main()
