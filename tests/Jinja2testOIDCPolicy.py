import jinja2


def main():


    from jinja2 import Environment, PackageLoader, select_autoescape
    env = Environment(
        loader=PackageLoader('Jinja2testOIDCPolicy', "..\\templates"),
        autoescape=select_autoescape(['html', 'xml', 'json', 'jinja2'])
    )

    template = env.get_template('Template_OIDCPolicy.jinja2')
    
    oidc_dict = {
        "pfClientId":"TestPID002",
        "pfRestrictIPInternal":True,
        "pfIncludeGroups":True,
        "pfRestrictToGroup":True,
        "pfRestrictedGroup":"SSO Admins"
    }

    print (template.render(oidc_dict))


if __name__ == '__main__':
    main()