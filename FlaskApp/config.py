

OAUTH2_PROVIDERS = {
    'asana': {
        'client_id': '1207748466259067',
        'client_secret': 'e558cdb75fc66b0e7cb7536fb4c347e4',
        'authorize_url': 'https://app.asana.com/-/oauth_authorize',
        'token_url': 'https://app.asana.com/-/oauth_token',
        'redirect_uri':'http://localhost:5000/callback/asana',
        'oauth2_token':'None'
    },
    'quickbooks': {
        'client_id' : 'ABWPxPcJE11ljqsv2CXOStc1dFPcRXFbJWuycqEdE50croJPk8',
        'client_secret' : 'vkQZWZKJi63rDHG74g9riYYRg1Dk8W4IcD7JcmIe',
        'redirect_uri':"http://localhost:5000/callback"
    }
}

ENVIRONMENT = 'sandbox'

# gid of tasks & fields in Asana
ASANA_GID = {
    'invoice' : '1207746538402679',
    'item' : '1207748437685985'
}


WEBHOOK_URL = 'https://2992-174-127-245-175.ngrok-free.app'

 
