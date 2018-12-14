import jinja2


def main():


    from jinja2 import Environment, PackageLoader, select_autoescape
    env = Environment(
        loader=PackageLoader('Jinja2testAccessTokenManager', "..\\templates"),
        autoescape=select_autoescape(['html', 'xml', 'json', 'jinja2'])
    )

    template = env.get_template('Template_AccessTokenManager_Inherit_Update.jinja2')
    
    atm_dict = {
        "pfAccessTokenManagerParentId":"TestPID002",
        "pfClientId":"AbTest",        
        "pfssokeyid":"testkeyid",
        "set_jwks_path":False
    }

    print (template.render(atm_dict))


if __name__ == '__main__':
    main()