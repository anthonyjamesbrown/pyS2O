
# PYS2O - Python Single Sign On Library for PingFederate

## SYNOPSIS
This project was written to be used with AWS Lambda to automate SSO tasks using serverless architecture.

## DESCRIPTION
This project used Jinja and Json templates to build configuration files to be consumed by the PingFederate REST API.

### Get Functions
* get_pf_access_token_manager (server_name, username, password, clientid)
* get_pf_access_token_manager_list (server_name, username, password)
* get_pf_access_token_manager_mapping (server_name, username, password, clientid)
* get_pf_access_token_manager_mapping_list (server_name, username, password)
* get_pf_authentication_policy_contracts (server_name, username, password)
* get_pf_cluster_status (server_name, username, password)
* get_pf_data_store (server_name, username, password, id=0)
* get_pf_idp_adapter (server_name, username, password, id=0)
* get_pf_idp_adapter_descriptor (server_name, username, password)
* get_pf_kerberos_realm (server_name, username, password, id=0)
* get_pf_kerberos_realm_setting (server_name, username, password)
* get_pf_oauth_client (server_name, username, password, clientid)
* get_pf_oauth_client_list (server_name, username, password)
* get_pf_oauth_token (server_name, username, password)
* get_pf_openid_connect_policy (server_name, username, password, id=0)
* get_pf_password_credential_validator (server_name, username, password, id=0)
* get_pf_signing_keypair (server_name, username, password, subject_dn, item_property)
* get_pf_sp_connection (server_name, username, password, id=0)
* get_pf_version (server_name, username, password):

### Config Generator Functions - Use templates and Jinja2 to generate JSON SSO configs
* generate_config_pf_oauth_client (clientid, grant_type, client_secret='', redirect_uris=[], restricted_scopes=['email', 'openid', 'profile'])
* generate_config_pf_oidc_policy (clientid, vds_datastore_id, include_groups=True, restrict_ip_internal=False, restrict_to_group=False, restricted_group='')
* generate_config_pf_access_token_manager_initial (clientid, ssokeyid, atm_parent_id)
* generate_config_pf_access_token_manager_update (clientid, ssokeyid, atm_parent_id, set_jwks_path=False)
* generate_config_pf_access_token_mapping (clientid, datastore_id, user_key_attribute)

### 'Invoke' and 'Import' Fuctions - Misc
* import_pf_signing_keypair (server_name, username, password, path, cert_password)
* invoke_pf_cluster_replication (server_name, username, password)

### 'Set' Functions - Post data to the PF Admin API
* set_pf_access_token_manager (server_name, username, password, config, action='update')
* set_pf_oidc_policy (server_name, username, password, config, action='update')
* set_pf_oauth_client (server_name, username, password, config, action='update')

### New Functions - Functions that leverage other functions to create new items in PF Admin API
* new_pf_access_token_manager (server_name, username, password, clientid)
* new_pf_oidc_policy (server_name, username, password, clientid, include_groups=True, restrict_ip_internal=False, restrict_to_group=False, restricted_group='')
* new_pf_oauth_client (server_name, username, password, clientid, grant_type, client_secret='', redirect_uris=[], restricted_scopes=['email', 'openid', 'profile'])
* new_pf_access_token_manager_mapping (server_name, username, password, clientid, user_key_attribute='userPrincipalName')
* new_pf_oidc_connection (server_name, username, password, clientid, grant_type, redirect_uris=[], restricted_scopes=['email', 'openid', 'profile'], include_groups=True,
        restrict_ip_internal=False, restrict_to_group=False, restricted_group='', atm_parent_id='UPN', set_jwks_path=False)
* new_pf_client_secret ()

## RELATED LINKS
