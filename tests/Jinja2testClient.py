import jinja2


def main():


    from jinja2 import Environment, PackageLoader, select_autoescape
    env = Environment(
        loader=PackageLoader('Jinja2testClient', "..\\templates"),
        autoescape=select_autoescape(['html', 'xml', 'json', 'jinja2'])
    )

    template = env.get_template('Template_Client.jinja2')
    
    client_secret = "vVABJtQzhawEo1Hqxfu6D7RXb5sg98TLiIGkdeyj3ZprW0FUOKlnYCPMm4cS2N"

    client_dict = {
        "pfClientId":"TestPID002",
        "pfRedirectURIs":['http://localhost/login','http://ucsinfo.int.company.com/'],        
        "pfRestrictedScopes":['email', 'openid', 'profile'],
        "pfGrantType":"IMPLICIT",
        "pfClientSecret": client_secret
    }

    print (template.render(client_dict))


if __name__ == '__main__':
    main()