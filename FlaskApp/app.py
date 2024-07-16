from flask import Flask, render_template, redirect, request, session, abort, make_response 
import asana, hmac ,json , hashlib , requests , secrets
import config
from intuitlib.client import AuthClient
from intuitlib.enums import Scopes
from quickbooks import QuickBooks
from quickbooks.objects.customer import Customer
from asana.rest import ApiException
from pprint import pprint
from urllib.parse import urlencode
from quickbooks.objects.item import Item
"""
"""
app = Flask(__name__)
app.secret_key = "dev key" 

qbo_auth = config.OAUTH2_PROVIDERS['quickbooks']
#setup and call QBO authorization
auth_client = AuthClient (
                            environment=config.ENVIRONMENT,
                            client_id=qbo_auth['client_id'], 
                            client_secret =qbo_auth['client_secret'],
                            redirect_uri = qbo_auth['redirect_uri']

)

scopes = [
            Scopes.ACCOUNTING
]


auth_url = auth_client.get_authorization_url(scopes)
@app.route('/qbo-login', methods = ['GET'])
def button():
    return redirect(auth_url)

# get qbo access token
@app.route('/callback', methods=['GET','POST'])
def qboCallback():
    auth_code = str(request.args.get('code'))
    realm_id = str(request.args.get('realmId'))
    auth_client.get_bearer_token(auth_code,realm_id=realm_id)
    session['new_token'] = auth_client.refresh_token
    session['realm_id'] = auth_client.realm_id
    return render_template('index.html')

#setup and call asana authorization

asana_auth = config.OAUTH2_PROVIDERS['asana']
@app.route('/login',methods=['GET','POST'])
def asanaLogin():
    global asana_auth
    session['state'] = secrets.token_urlsafe(16)
    qs = urlencode({
        'client_id': asana_auth['client_id'],
        'redirect_uri': asana_auth['redirect_uri'],
        'response_type': 'code',
        'state': session['state'],
    })
    redirect_uri = asana_auth['authorize_url'] + '?' + qs
    return redirect(redirect_uri)

#asana callback


@app.route('/callback/asana', methods=['GET','POST'])
def asanaCallback():
    global asana_auth
    auth_code = str(request.args.get('code'))
    response = requests.post(asana_auth['token_url'], data={
        'client_id': asana_auth['client_id'],
        'client_secret': asana_auth['client_secret'],
        'code': auth_code,
        'grant_type': 'authorization_code',
        'redirect_uri': asana_auth['redirect_uri']
    }, headers={'Accept': 'application/json'})
    if response.status_code != 200:
        abort(401)
    asana_auth['oauth2_token'] = response.json().get('access_token')
    if not asana_auth['oauth2_token'] :
        abort(401)
    return render_template('index.html')


itemDetail = ''  

# data mapping
def mapData():
    data = session['event_data']
    str_data = data.decode('utf-8')
    json_data = json.loads(str_data)
    task_change = json_data["events"][0]['change']
    if (task_change['action']) == 'changed':
         change_ID = task_change["new_value"]["enum_value"]["gid"]
         return change_ID


# post data to QBO
@app.route("/call-qbo",methods=['GET','POST'])
def callQbo():
    global itemDetail
    change_ID = mapData()
    print(change_ID)
    
    if change_ID == config.ASANA_GID['item']:
        body =  {
                        "TrackQtyOnHand": True, 
                        "Name": "Servicing Equipment", 
                        "QtyOnHand": 3, 
                    "IncomeAccountRef": 
                        {
                        "name": "Sales of Product Income", 
                        "value": "79"
                        }, 
                    "AssetAccountRef":
                        {
                        "name": "Inventory Asset", 
                        "value": "81"
                        }, 
                     "InvStartDate": "2016-01-01", 
                     "Type": "Inventory", 
                     "ExpenseAccountRef":
                        {
                                "name": "Cost of Goods Sold", 
                                "value": "80"
                        }
                    }
        base_url = 'https://{0}-quickbooks.api.intuit.com'.format(config.ENVIRONMENT)
        url = '{0}/v3/company/{1}/item'.format(base_url, auth_client.realm_id)
        auth_header = 'Bearer {0}'.format(auth_client.access_token)
        headers = {
        'Authorization': auth_header,
        'Accept': 'application/json'
        }
        response = requests.post(url, headers=headers, json=body)   
        print(response.content)
        itemDetail = response.content.decode('utf-8')
    if change_ID == config.ASANA_GID['invoice']:
                    str_item = itemDetail
                    json_item = json.loads(str_item)
                    itemID = json_item['Item']['Id']
                    body =  {
                                "Line": [
                                    {
                                      "DetailType": "SalesItemLineDetail", 
                                      "Amount": 100.0, 
                                     "SalesItemLineDetail": {
                                     "ItemRef": {
                                      "name": "Services", 
                                      "value": itemID
                                     },
                                "Qty": 1.0
                                        }
                                    }
                                         ], 
                            "CustomerRef": {
                              "value": "1"
                                             }
                            }
                    base_url = 'https://{0}-quickbooks.api.intuit.com'.format(config.ENVIRONMENT)
                    inv_url = '{0}/v3/company/{1}/invoice'.format(base_url, auth_client.realm_id)
                    auth_header = 'Bearer {0}'.format(auth_client.access_token)
                    headers = {
                    'Authorization': auth_header,
                    'Accept': 'application/json'
                    }
                    inv_response = requests.post(inv_url, headers=headers, json=body)   
                    print(inv_response.content)
                    session['invoiceDetail'] = inv_response.content
                    createTask()
    return render_template('index.html')


# receive events from asana
#hook_secret = None

#@app.route("/create-webhook", methods=["GET", 'POST'])


@app.route("/receive-webhook",methods=['GET','POST'])
def webhook():
    config.hook_secret
    #print("Inside webhook")
    #print("Header")
    #pprint(request.headers)
    app.logger.info("Headers: \n" + str(request.headers))
    app.logger.info("Body: \n" + str(request.data))
    print("This is data",request.data)
    session['event_data'] = request.data
    if "X-Hook-Secret" in request.headers:
        if config.hook_secret is not None:
            app.logger.warn("Second handshake request received. This could be an attacker trying to set up a new secret. Ignoring.")
        else:
            # Respond to the handshake request :)
            app.logger.info("New webhook")
            response = make_response("", 200)
            # Save the secret for later to verify incoming webhooks
            config.hook_secret = request.headers["X-Hook-Secret"]
            response.headers["X-Hook-Secret"] = request.headers["X-Hook-Secret"]
            response.data = "Success"
            pprint(response.data)
            pprint(response.headers)
            return response
    elif "X-Hook-Signature" in request.headers:
        # Compare the signature sent by Asana's API with one calculated locally.
        # These should match since we now share the same secret as what Asana has stored.
        if isinstance(request.data,str):
            data_bytes = request.data.encode('ascii', 'ignore')
        else:
            data_bytes = request.data
        signature = hmac.new(config.hook_secret.encode('ascii', 'ignore'),
                msg=data_bytes, digestmod=hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature.encode('ascii', 'ignore'),
                request.headers["X-Hook-Signature"].encode('ascii', 'ignore')):
            app.logger.warn("Calculated digest does not match digest from API. This event is not trusted.")
            return
        contents = json.loads(request.data)
        app.logger.info("Received payload of %s events", len(contents["events"]))
        data = json.loads(request.data.decode('utf-8'))
        print('sig data')
        pprint(data)
        if 'events' in data and data['events']: 
            callQbo()
        return ""
    else:
        raise KeyError

@app.route("/asanaTask", methods=['GET', 'POST'])
def createTask():
    str_data = session['invoiceDetail'].decode('utf-8')
    json_data = json.loads(str_data)
    invoiceID = json_data["Invoice"]["DocNumber"]
    companyName = json_data["Invoice"]["CustomerRef"]['name']
    configuration = asana.Configuration()
    configuration.access_token = asana_auth['oauth2_token']
    api_client = asana.ApiClient(configuration)

    # create task
    tasks_api_instance = asana.TasksApi(api_client)
    project_gid = '1207746538402651'
    body = {"data": 
            {"workspace": "1207746425168483", 
             "name": 'Check payment for invoiceID {0} from {1}'.format(invoiceID,companyName) , 
             "assignee": "me",
             "projects" :[project_gid]
             }
            }
   
    opts = {}
    try:
        task = tasks_api_instance.create_task(body, opts)
        pprint(task)
    except ApiException as e:
        print("Exception when calling TasksApi->create_task: %s\n" % e) 
    return render_template('index.html')


@app.route('/', methods =['GET', 'POST'] )
def home():
    return render_template('index.html')



"""
app.config['OAUTH2_PROVIDERS'] = {
    'asana': {
        'client_id': '1207748466259067',
        'client_secret': 'e558cdb75fc66b0e7cb7536fb4c347e4',
        'authorize_url': 'https://app.asana.com/-/oauth_authorize',
        'token_url': 'https://app.asana.com/-/oauth_token',
        'redirect_uri':'http://localhost:5000/callback/asana',
        'oauth2_token':'None'
    },
}

    new_token = session.get('new_token', None)
    realm_id = session.get('realm_id', None)
        
    client = QuickBooks(
                     auth_client = auth_client,
                     refresh_token = new_token,
                     company_id = realm_id)  
#print("refresh",auth_client.refresh_token)
Asana Token:
2/1207746425168472/1207748354223553:d9f95607af721d5a8cf8832fb4571f95
Asana Workspace
{
  "data" : [ {
    "gid" : "1207746425168483",
    "name" : "My workspace",
    "resource_type" : "workspace"
  } ]
}Create Task
https://app.asana.com/api/1.0/tasks


"""



"""
create task
tasks_api_instance = asana.TasksApi(api_client)
body = {"data": {"workspace": "1207746425168483", "name": "Sample order create", "assignee": "me"}}
opts = {}


try:
    task = tasks_api_instance.create_task(body, opts)
    pprint(task)
except ApiException as e:
    print("Exception when calling TasksApi->create_task: %s\n" % e)

"""
"""
get task

tasks_api_instance = asana.TasksApi(api_client)
task_gid = "1207748432254156"
opts = { 
    'opt_fields': "name,assignee,workspace"
}

try:
    task = tasks_api_instance.get_task(task_gid, opts)
    pprint(task)
except ApiException as e:
    print("Exception when calling TasksApi->get_task: %s\n" % e)
"""
"""
update task
tasks_api_instance = asana.TasksApi(api_client)
body = {"data": 
        {"name": "Modified task",}}
task_gid = "1207748432254156"
opts = { 
    'opt_fields': "name,assignee,workspace"
}

try:
    task = tasks_api_instance.update_task(body, task_gid, opts)
    pprint(task)
except ApiException as e:
    print("Exception when calling TasksApi->update_task: %s\n" % e)

"""

"""
projects_api_instance = asana.ProjectsApi(api_client)
opts = {
    
    'workspace': "1207746425168483", # str | The workspace or organization to filter projects on.
    'archived': False, # bool | Only return projects whose `archived` field takes on the value of this parameter.
    'opt_fields': "archived,color,completed,completed_at,completed_by,completed_by.name,created_at,created_from_template,created_from_template.name,current_status,current_status.author,current_status.author.name,current_status.color,current_status.created_at,current_status.created_by,current_status.created_by.name,current_status.html_text,current_status.modified_at,current_status.text,current_status.title,current_status_update,current_status_update.resource_subtype,current_status_update.title,custom_field_settings,custom_field_settings.custom_field,custom_field_settings.custom_field.asana_created_field,custom_field_settings.custom_field.created_by,custom_field_settings.custom_field.created_by.name,custom_field_settings.custom_field.currency_code,custom_field_settings.custom_field.custom_label,custom_field_settings.custom_field.custom_label_position,custom_field_settings.custom_field.date_value,custom_field_settings.custom_field.date_value.date,custom_field_settings.custom_field.date_value.date_time,custom_field_settings.custom_field.description,custom_field_settings.custom_field.display_value,custom_field_settings.custom_field.enabled,custom_field_settings.custom_field.enum_options,custom_field_settings.custom_field.enum_options.color,custom_field_settings.custom_field.enum_options.enabled,custom_field_settings.custom_field.enum_options.name,custom_field_settings.custom_field.enum_value,custom_field_settings.custom_field.enum_value.color,custom_field_settings.custom_field.enum_value.enabled,custom_field_settings.custom_field.enum_value.name,custom_field_settings.custom_field.format,custom_field_settings.custom_field.has_notifications_enabled,custom_field_settings.custom_field.id_prefix,custom_field_settings.custom_field.is_formula_field,custom_field_settings.custom_field.is_global_to_workspace,custom_field_settings.custom_field.is_value_read_only,custom_field_settings.custom_field.multi_enum_values,custom_field_settings.custom_field.multi_enum_values.color,custom_field_settings.custom_field.multi_enum_values.enabled,custom_field_settings.custom_field.multi_enum_values.name,custom_field_settings.custom_field.name,custom_field_settings.custom_field.number_value,custom_field_settings.custom_field.people_value,custom_field_settings.custom_field.people_value.name,custom_field_settings.custom_field.precision,custom_field_settings.custom_field.representation_type,custom_field_settings.custom_field.resource_subtype,custom_field_settings.custom_field.text_value,custom_field_settings.custom_field.type,custom_field_settings.is_important,custom_field_settings.parent,custom_field_settings.parent.name,custom_field_settings.project,custom_field_settings.project.name,custom_fields,custom_fields.date_value,custom_fields.date_value.date,custom_fields.date_value.date_time,custom_fields.display_value,custom_fields.enabled,custom_fields.enum_options,custom_fields.enum_options.color,custom_fields.enum_options.enabled,custom_fields.enum_options.name,custom_fields.enum_value,custom_fields.enum_value.color,custom_fields.enum_value.enabled,custom_fields.enum_value.name,custom_fields.id_prefix,custom_fields.is_formula_field,custom_fields.multi_enum_values,custom_fields.multi_enum_values.color,custom_fields.multi_enum_values.enabled,custom_fields.multi_enum_values.name,custom_fields.name,custom_fields.number_value,custom_fields.representation_type,custom_fields.resource_subtype,custom_fields.text_value,custom_fields.type,default_access_level,default_view,due_date,due_on,followers,followers.name,html_notes,icon,members,members.name,minimum_access_level_for_customization,minimum_access_level_for_sharing,modified_at,name,notes,offset,owner,path,permalink_url,privacy_setting,project_brief,public,start_on,team,team.name,uri,workspace,workspace.name", # list[str] | This endpoint returns a compact resource, which excludes some properties by default. To include those optional properties, set this query parameter to a comma-separated list of the properties you wish to include.
}

try:
    # Get multiple projects
    api_response = projects_api_instance.get_projects(opts)
    for data in api_response:
        pprint(data)
except ApiException as e:
    print("Exception when calling ProjectsApi->get_projects: %s\n" % e)
    # @app.route('/', methods =['GET', 'POST'] )
# def home():
#     return render_template('index.html')



#print("refresh",auth_client.refresh_token)

"""

"""
@app.route('/api', methods=['GET','POST'])
def asanaconfig():
    asana_auth = app.config['OAUTH2_PROVIDERS'].get('asana')
    configuration = asana.Configuration()
    configuration.access_token = asana_auth['oauth2_token']
    api_client = asana.ApiClient(configuration)
    projects_api_instance = asana.ProjectsApi(api_client)
    opts = {
    
    'workspace': "1207746425168483", # str | The workspace or organization to filter projects on.
    'archived': False, # bool | Only return projects whose `archived` field takes on the value of this parameter.
    'opt_fields': "archived,color,completed,completed_at,completed_by,completed_by.name,created_at,created_from_template,created_from_template.name,current_status,current_status.author,current_status.author.name,current_status.color,current_status.created_at,current_status.created_by,current_status.created_by.name,current_status.html_text,current_status.modified_at,current_status.text,current_status.title,current_status_update,current_status_update.resource_subtype,current_status_update.title,custom_field_settings,custom_field_settings.custom_field,custom_field_settings.custom_field.asana_created_field,custom_field_settings.custom_field.created_by,custom_field_settings.custom_field.created_by.name,custom_field_settings.custom_field.currency_code,custom_field_settings.custom_field.custom_label,custom_field_settings.custom_field.custom_label_position,custom_field_settings.custom_field.date_value,custom_field_settings.custom_field.date_value.date,custom_field_settings.custom_field.date_value.date_time,custom_field_settings.custom_field.description,custom_field_settings.custom_field.display_value,custom_field_settings.custom_field.enabled,custom_field_settings.custom_field.enum_options,custom_field_settings.custom_field.enum_options.color,custom_field_settings.custom_field.enum_options.enabled,custom_field_settings.custom_field.enum_options.name,custom_field_settings.custom_field.enum_value,custom_field_settings.custom_field.enum_value.color,custom_field_settings.custom_field.enum_value.enabled,custom_field_settings.custom_field.enum_value.name,custom_field_settings.custom_field.format,custom_field_settings.custom_field.has_notifications_enabled,custom_field_settings.custom_field.id_prefix,custom_field_settings.custom_field.is_formula_field,custom_field_settings.custom_field.is_global_to_workspace,custom_field_settings.custom_field.is_value_read_only,custom_field_settings.custom_field.multi_enum_values,custom_field_settings.custom_field.multi_enum_values.color,custom_field_settings.custom_field.multi_enum_values.enabled,custom_field_settings.custom_field.multi_enum_values.name,custom_field_settings.custom_field.name,custom_field_settings.custom_field.number_value,custom_field_settings.custom_field.people_value,custom_field_settings.custom_field.people_value.name,custom_field_settings.custom_field.precision,custom_field_settings.custom_field.representation_type,custom_field_settings.custom_field.resource_subtype,custom_field_settings.custom_field.text_value,custom_field_settings.custom_field.type,custom_field_settings.is_important,custom_field_settings.parent,custom_field_settings.parent.name,custom_field_settings.project,custom_field_settings.project.name,custom_fields,custom_fields.date_value,custom_fields.date_value.date,custom_fields.date_value.date_time,custom_fields.display_value,custom_fields.enabled,custom_fields.enum_options,custom_fields.enum_options.color,custom_fields.enum_options.enabled,custom_fields.enum_options.name,custom_fields.enum_value,custom_fields.enum_value.color,custom_fields.enum_value.enabled,custom_fields.enum_value.name,custom_fields.id_prefix,custom_fields.is_formula_field,custom_fields.multi_enum_values,custom_fields.multi_enum_values.color,custom_fields.multi_enum_values.enabled,custom_fields.multi_enum_values.name,custom_fields.name,custom_fields.number_value,custom_fields.representation_type,custom_fields.resource_subtype,custom_fields.text_value,custom_fields.type,default_access_level,default_view,due_date,due_on,followers,followers.name,html_notes,icon,members,members.name,minimum_access_level_for_customization,minimum_access_level_for_sharing,modified_at,name,notes,offset,owner,path,permalink_url,privacy_setting,project_brief,public,start_on,team,team.name,uri,workspace,workspace.name", # list[str] | This endpoint returns a compact resource, which excludes some properties by default. To include those optional properties, set this query parameter to a comma-separated list of the properties you wish to include.
    }

    try:
    # Get multiple projects
        api_response = projects_api_instance.get_projects(opts)
        for data in api_response:
            pprint(data)
    except ApiException as e:
        print("Exception when calling ProjectsApi->get_projects: %s\n" % e)
    return render_template('index.html')
"""

"""

@app.route("/create-webhook", methods=["GET", 'POST'])
def create_hook():
    configuration = asana.Configuration()
    configuration.access_token = '2/1207746425168472/1207748354223553:d9f95607af721d5a8cf8832fb4571f95'
    api_client = asana.ApiClient(configuration)
    webhooks_api_instance = asana.WebhooksApi(api_client)
    body =     { "data": {
                            "resource": "1207746538402651",
                             "target": "https://8aca-174-127-245-175.ngrok-free.app/receive-webhook",
                 "filters": [
                            {
                 "action": "changed",
                "resource_type": "task"
                }
                             ]
                            }} # dict | The webhook workspace and target.
    opts = {
    'opt_fields': "active,created_at,filters,filters.action,filters.fields,filters.resource_subtype,last_failure_at,last_failure_content,last_success_at,resource,resource.name,target", # list[str] | This endpoint returns a compact resource, which excludes some properties by default. To include those optional properties, set this query parameter to a comma-separated list of the properties you wish to include.
    }
    return render_template("index.html")
"""
"""
@app.route("/get-webhook", methods=["GET", 'POST'])
def get_webhook():
    configuration = asana.Configuration()
    configuration.access_token = '2/1207746425168472/1207748354223553:d9f95607af721d5a8cf8832fb4571f95'
    api_client = asana.ApiClient(configuration)
    webhooks_api_instance = asana.WebhooksApi(api_client)
    webhook_gid = "1207799855101363" # str | Globally unique identifier for the webhook.
    hook_secret = b09b277e8f77615a4d1d3eea0aa34c93
    opts = {
    'opt_fields': "active,created_at,filters,filters.action,filters.fields,filters.resource_subtype,last_failure_at,last_failure_content,last_success_at,resource,resource.name,target", # list[str] | This endpoint returns a compact resource, which excludes some properties by default. To include those optional properties, set this query parameter to a comma-separated list of the properties you wish to include.
    }

    try:
    # Get a webhook
        api_response = webhooks_api_instance.get_webhook(webhook_gid, opts)
        pprint(api_response)
    except ApiException as e:
        print("Exception when calling WebhooksApi->get_webhook: %s\n" % e)
    return render_template('index.html')
"""
"""
# create an instance of the API class
 
    workspace = "1207746425168483"
Established webhook
{
    "data": {
        "gid": "1207749977080033",
        "resource_type": "webhook",
        "last_failure_content": "",
        "last_failure_at": null,
        "created_at": "2024-07-06T21:50:07.371Z",
        "is_workspace_webhook": false,
        "last_success_at": "2024-07-06T21:50:07.778Z",
        "target": "https://5836-174-127-245-175.ngrok-free.app/receive-webhook",
        "active": true,
        "filters": [
            {
                "resource_type": "task",
                "resource_subtype": null,
                "action": "changed",
                "fields": null
            }
        ],
        "resource": {
            "gid": "1207746538402651",
            "resource_type": "project",
            "name": "eStore"
        }
    },
    "X-Hook-Secret": "a8cd140b1f04959c7a8b9074c834c590"
}

"""



#print(auth_url)
app.run(port=5000)
