import json
import os

# Imports the Google Cloud client library
from google.cloud.datastore import Client, Entity
from flask import abort, make_response
from google.oauth2 import id_token
from google.auth.transport import requests

from google.cloud import storage
from google.cloud import bigquery


# Environment variables

# name of application authorization group -- must be a name of kind
GROUPNAME = "clio_toplevel"
OWNER = os.environ["OWNER"]

# constants for signature search
SIG_BUCKET = os.environ["SIG_BUCKET"]
SIG_CACHE = None # dataset to meta data caache for signature image search
SIG_DATASET_SUFFIX = "_imgsearch"
MAX_DISTANCE = 100 # 100 pixels (TODO: make dynamic) 

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

# helper function for getting sig/xyz for x,y,z
def fetch_signature(dataset, x, y, z):
    global SIG_CACHE
    storage_client = storage.Client()
    bucket = storage_client.bucket(SIG_BUCKET)

    # fetch metaadata
    meta = None
    if SIG_CACHE is not None and dataset in SIG_CACHE:
        meta = SIG_CACHE[dataset]
    else:
        blob = bucket.blob(dataset + "/info.json") 
        try:
            meta = json.loads(blob.download_as_string())
            if SIG_CACHE is None:
                SIG_CACHE = {}
            SIG_CACHE[dataset] = meta
        except Exception as e:
            print(e)
            raise Exception("dataset not found")

    block_size = meta["block_size"]

    # TODO: get stride information from info and predict perfect coordinate or design sampling
    # so block boundaries do not contain samples
    xb = x // block_size
    yb = y // block_size
    zb = z // block_size

    closest_dist = 999999999999
    closest_point = [0, 0, 0]
    closest_sig = 0

    def distance(pt):
        return (((x-pt[0])**2 + (y-pt[1])**2 + (z-pt[2])**2)**(0.5))
    
    # grab block and find closest match
    try:
        RECORD_SIZE = 20 # 20 bytes per x,y,z,signature
        blob = bucket.blob(dataset + f"/blocks/{xb}_{yb}_{zb}")
        blockbin = blob.download_as_string()
        records = len(blockbin) // RECORD_SIZE

        for record in range(records):
            start = record*RECORD_SIZE
            xt = int.from_bytes(blockbin[start:(start+4)], "little")
            start += 4
            yt = int.from_bytes(blockbin[start:(start+4)], "little")
            start += 4
            zt = int.from_bytes(blockbin[start:(start+4)], "little")
            start += 4
            dist = distance((xt,yt,zt))
            if dist <= MAX_DISTANCE and dist < closest_dist:
                closest_dist = dist
                closest_point = [xt,yt,zt]
                closest_sig = int.from_bytes(blockbin[start:(start+8)], "little", signed=True) # make signed int
        if closest_dist > MAX_DISTANCE:
            raise Exception("point not found")
    except Exception:
        raise Exception("point not found")

    return closest_point, closest_sig

def murmur64(h):
    h ^= h >> 33
    h *= 0xff51afd7ed558ccd
    h &= 0xFFFFFFFFFFFFFFFF 
    h ^= h >> 33
    h *= 0xc4ceb9fe1a85ec53
    h &= 0xFFFFFFFFFFFFFFFF 
    h ^= h >> 33
    return h

# find the closest signatures by hamming distance
def find_similar_signatures(dataset, x, y, z):
    # don't catch error if there is one
    point, signature = fetch_signature(dataset, x, y, z)
    meta = SIG_CACHE[dataset]    
    PARTITIONS = 4000

    # find partitions for the signature
    part0 = murmur64(int(meta["ham_0"]) & signature) % PARTITIONS
    part1 = murmur64(int(meta["ham_1"]) & signature) % PARTITIONS
    part2 = murmur64(int(meta["ham_2"]) & signature) % PARTITIONS
    part3 = murmur64(int(meta["ham_3"]) & signature) % PARTITIONS
   
    """
    part0 = murmur64(signature) % PARTITIONS
    part1 = murmur64(signature) % PARTITIONS
    part2 = murmur64(signature) % PARTITIONS
    part3 = murmur64(signature) % PARTITIONS
    """

    max_ham = 8

    SQL = f"SELECT signature, BIT_COUNT(signature^{signature}) AS hamming, x, y, z FROM `{dataset}{SIG_DATASET_SUFFIX}.hamming0`\nWHERE part={part0} AND BIT_COUNT(signature^{signature}) < {max_ham}\nUNION DISTINCT\n"
    SQL += f"SELECT signature, BIT_COUNT(signature^{signature}) AS hamming, x, y, z FROM `{dataset}{SIG_DATASET_SUFFIX}.hamming1`\nWHERE part={part1} AND BIT_COUNT(signature^{signature}) < {max_ham}\nUNION DISTINCT\n"
    SQL += f"SELECT signature, BIT_COUNT(signature^{signature}) AS hamming, x, y, z FROM `{dataset}{SIG_DATASET_SUFFIX}.hamming2`\nWHERE part={part2} AND BIT_COUNT(signature^{signature}) < {max_ham}\nUNION DISTINCT\n"
    SQL += f"SELECT signature, BIT_COUNT(signature^{signature}) AS hamming, x, y, z FROM `{dataset}{SIG_DATASET_SUFFIX}.hamming3`\nWHERE part={part3} AND BIT_COUNT(signature^{signature}) < {max_ham}\n"
    SQL += f"ORDER BY BIT_COUNT(signature^{signature}), rand()\nLIMIT 200" 

    client = bigquery.Client()

    query_job = client.query(SQL)
    results = query_job.result()
    
    all_points = [[x,y,z]]
    def distance(pt):
        best = 999999999999
        for c in all_points:
            temp = (((c[0]-pt[0])**2 + (c[1]-pt[1])**2 + (c[2]-pt[2])**2)**(0.5))
            if temp < best:
                best = temp
        return best

    pruned_results = []
    for row in results:
        # load results
        if distance((row.x, row.y, row.z)) > MAX_DISTANCE: 
            pruned_results.append({"point": [row.x, row.y, row.z], "dist": row.hamming, "score": (1.0-row.hamming/max_ham)})
            all_points.append([row.x, row.y, row.z])

    return pruned_results

def getSignature(roles, dataset, point):
    if "clio_general" not in roles:
        abort(403)

    try:
        pt, sig = fetch_signature(dataset, *point)
        res = {"point": pt, "signature": str(sig)}
    except Exception as e:
        res = {"messsage": str(e)}
    return json.dumps(res)

def getMatches(roles, dataset, point):
    if "clio_general" not in roles:
        abort(403)

    try:
        data = find_similar_signatures(dataset, *point)
        res = {"matches": data}
        if len(data) == 0:
            res["message"] = "no matches"
    except Exception as e:
        res = {"messsage": str(e)}
    return json.dumps(res)

# TODO: function for calling thumbnail -- I could just relay the call for now

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
    elif urlparts[0] == "signatures" and len(urlparts) == 3 and urlparts[1] == "atlocation":
        dataset = urlparts[2]
        # not necessary for a GET request
        x = int(request.args.get('x'))
        y = int(request.args.get('y'))
        z = int(request.args.get('z'))
        resp = getSignature(roles, dataset, (x,y,z))
    elif urlparts[0] == "signatures" and len(urlparts) == 3 and urlparts[1] == "likelocation":
        dataset = urlparts[2]
        # not necessary for a GET request
        x = int(request.args.get('x'))
        y = int(request.args.get('y'))
        z = int(request.args.get('z'))
        resp = getMatches(roles, dataset, (x,y,z))
    else:
        abort(400)

    resp = make_response(resp)
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    resp.headers['Access-Control-Allow-Methods'] = 'POST, GET, DELETE, OPTIONS'
    return resp

