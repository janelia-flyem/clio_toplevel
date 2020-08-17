import json
import os

# Imports the Google Cloud client library
from google.cloud.datastore import Client, Entity
from flask import abort, make_response
from google.oauth2 import id_token
from google.auth.transport import requests

# Environment variables

# name of application authorization group -- must be a name of kind
GROUPNAME = "clio_toplevel"
OWNER = os.environ["OWNER"]

USER_CACHE = None

def handlerAnnotations(roles, dataset, point, jsondata, method):
    """Enables annotations for a dataset.
    
    Data is stored indexed uniquely to an x,y,z.  Post
    should only be one synapse at a time.  The json payload
    is arbitrary.
    """
    if "clio_general" not in roles:
        abort(403)

    # Instantiates a client
    client = Client()
    # The kind for the new entity
    kind = GROUPNAME
    # The Cloud Datastore key for the new entity
    key = client.key(kind, dataset+"_annotations")

    if method == "GET":
        try:
            task = client.get(key)
            # no annotations saved
            if not task:
                return json.dumps({})
            return json.dumps(task)
        except Exception as e:
            return abort(400)
    elif method == "POST" or method == "PUT":
        try:
            with client.transaction():
                task = client.get(key)
                if not task:
                    task = Entity(key)
                point_str = str(point[0]) + "_" + str(point[1]) + "_" + str(point[2])
                payload = {}
                payload[point_str] = jsondata
                task.update(payload)
                client.put(task)
        except:
            return abort(400)
    elif method == "DELETE":
        # info should be [ name1, name2, etc]
        try:
            with client.transaction():
                task = client.get(key)
                if not task:
                    return abort(400)
                else:
                    point_str = str(point[0]) + "_" + str(point[1]) + "_" + str(point[2])
                    if point_str in task:
                        del task[point_str]
                client.put(task)
        except Exception as e:
            print(e)
            return abort(400)
    else:
        return abort(400)

    return ""

def handlerDatasets(roles, dataset_info, method):
    """Manages dataset information.

    format:
    {name: [desc, location], name2: ... }

    Indexing is done on dataset name.  Multiple datasets
    can be added or deleted using the API.

    dataset_info is empty for a GET, is a diction
    for a POST, and is a list of datasets for a DELETE.
    """
    if "clio_general" not in roles:
        abort(403)

    if (method == "POST" or method == "DELETE" or method == "PUT") and "admin" not in roles and "owner" not in roles:
        return abort(403)

    # Instantiates a client
    client = Client()
    # The kind for the new entity
    kind = GROUPNAME
    # The Cloud Datastore key for the new entity
    key = client.key(kind, "datasets")

    if method == "GET":
        try:
            task = client.get(key)
            # no datasets saved
            if not task:
                return json.dumps({})
            return json.dumps(task)
        except Exception as e:
            return abort(400)
    elif method == "POST" or method == "PUT":
        try:
            with client.transaction():
                task = client.get(key)
                if not task:
                    task = Entity(key)
                task.update(dataset_info)
                client.put(task)
        except:
            return abort(400)
    elif method == "DELETE":
        # info should be [ name1, name2, etc]
        try:
            with client.transaction():
                task = client.get(key)
                if not task:
                    return abort(400)
                else:
                    for dataset in dataset_info:
                        del task[dataset]
                client.put(task)
        except Exception as e:
            print(e)
            return abort(400)
    else:
        return abort(400)

    return ""

def handlerUsers(roles, userdata, method):
    global USER_CACHE

    # allow owner to have access
    if "admin" not in roles and "owner" not in roles:
        return abort(403)

    # Instantiates a client
    client = Client()
    # The kind for the new entity
    kind = GROUPNAME
    # The Cloud Datastore key for the new entity
    key = client.key(kind, "users")

    if method == "GET":
        try:
            task = client.get(key)
            # no users saved
            if not task:
                return json.dumps({})
            return json.dumps(task)
        except Exception as e:
            return abort(400)
    elif method == "POST" or method == "PUT":
        try:
            with client.transaction():
                task = client.get(key)
                if not task:
                    task = Entity(key)
                task.update(userdata)
                USER_CACHE = task
                client.put(task)
        except:
            return abort(400)
    elif method == "DELETE":
        try:
            with client.transaction():
                task = client.get(key)
                if not task:
                    return abort(400)
                else:
                    for user in userdata:
                        del task[user]
                # update cache
                USER_CACHE = task

                client.put(task)
        except Exception as e:
            print(e)
            return abort(400)
    else:
        return abort(400)

    return ""

def get_auth(token):
    """Check google token and return user roles.
    """
    global USER_CACHE

    # verify it is up-to-date from Google -- throws exception if invalid
    idinfo = id_token.verify_oauth2_token(token, requests.Request()) 
   
    # grab lower-case version of email
    email = idinfo["email"].lower()
    roles = []

    # check cache first, requery if not there 
    if USER_CACHE is not None and email in USER_CACHE:
        roles = USER_CACHE[email]
    else:
        # load cache
        
        # Instantiates a client
        client = Client()
        # The kind for the new entity
        kind = GROUPNAME
        # The Cloud Datastore key for the new entity
        key = client.key(kind, "users")
        task = client.get(key)
        # no users saved
        if not task:
            USER_CACHE = {}
        else:
            USER_CACHE = task 

        if email not in USER_CACHE:
            if email != OWNER:
                roles = ["noauth"]
        else:
            roles = USER_CACHE[email]

    # add special owner role if relevant
    if email == OWNER and "owner" not in roles:
        roles.append("owner")

    return roles

def main(request):
    """Responds to any HTTP request.
    Args:
        request (flask.Request): HTTP request object.
    Returns:
        The response text or any set of values that can be turned into a
        Response object using
        `make_response <http://flask.pocoo.org/docs/0.12/api/#flask.Flask.make_response>`.
    """
    # handle preflight request
    if request.method == "OPTIONS":
        resp = make_response("")
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'POST, GET, DELETE, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
        return resp

    # extract google token
    auth = request.headers.get('authorization')
    if auth is None or auth == "":
        return abort(401)
    authlist = auth.split(' ')
    if len(authlist) != 2:
        return abort(401) # Bearer must be specified
    auth = authlist[1]

    # check user auth and populate cache
    roles = []
    try:
        roles = get_auth(auth)
    except Exception as e:
        abort(401)

    pathinfo = request.path.strip("/")
    urlparts = pathinfo.split('/')

    if len(urlparts) == 0:
        abort(400)

    # if data is posted it should be in JSON format
    jsondata = request.get_json(force=True, silent=True)

    # GET/POST/DELETE dataset information
    if urlparts[0] == "datasets":
        resp = handlerDatasets(roles, jsondata, request.method)
    # GET/POST/PUT/DELETE /annotations/[dataset]?x=X,y=Y,z=Z
    elif urlparts[0] == "annotations" and len(urlparts) == 2:
        dataset = urlparts[1]
        # not necessary for a GET request
        x = request.args.get('x')
        y = request.args.get('y')
        z = request.args.get('z')
        resp = handlerAnnotations(roles, dataset, (x,y,z), jsondata, request.method)
    # GET /users -- return all users and auth (admin)
    # POST /users -- add user and auth
    elif urlparts[0] == "users":
        resp = handlerUsers(roles, jsondata, request.method) 
    elif urlparts[0] == "roles":
        resp = json.dumps(roles)
    else:
        abort(400)

    resp = make_response(resp)
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    resp.headers['Access-Control-Allow-Methods'] = 'POST, GET, DELETE, OPTIONS'
    return resp

