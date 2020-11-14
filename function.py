import json
import os

# import firestore (deprecates datastore)
from google.cloud import firestore

from flask import abort, make_response
from google.oauth2 import id_token
from google.auth.transport import requests
import requests as requests2

from google.cloud import storage
from google.cloud import bigquery

import time
import threading
import string
import random
import traceback

# Environment variables

# name of application authorization group -- must be a name of kind
GROUPNAME = "clio_toplevel"
OWNER = os.environ["OWNER"]

# constants for signature search
SIG_BUCKET = os.environ["SIG_BUCKET"]
SIG_CACHE = None # dataset to meta data caache for signature image search
SIG_DATASET_SUFFIX = "_imgsearch"
MAX_DISTANCE = 100 # 100 pixels (TODO: make dynamic) 

# transfer cloud run location and destination bucket
TRANSFER_FUNC = os.environ["TRANSFER_FUNC"]
TRANSFER_DEST = os.environ["TRANSFER_DEST"]

USER_CACHE = {} 

"""Supported roles:

owner: settable in the environment, equals admin
admin: admin access to things like user roles
clio_general: clio read access and local writes (default if public)
clio_write: non-local write access


public mode: clio_general role for all authenticated users
"""

# firestore user collection name
CLIO_USERS = "clio_users"

# firestore dataset collection name
CLIO_DATASETS = "clio_datasets"

def transferData(email, jsondata):
    """Transfer data for the given dataset, location, and model.
    
    JSON format

    {
        "center": [x,y,z] # center point x,y,z
        "dataset": "dataset name",
        "model_name": "model_name" # must be listed in the dataset info
    }

    """
    
    roles = get_roles(email, dataset)
    if "clio_general" not in roles:
        abort(403)

    """Json schema for cloud run request.

    {
        "location": "bucket and data location",
        "start": [x,y,z], # where to start reading -- should be multiple 64 from global offset
        "glbstart": [x,y,z], # for 0,0,0 offset
        "size": [x,y,z]. # multiple of 64
        "model_name": "model:version",
        "dest": "bucket and dest location for neuroglancer"
    }
    """

    try:
        # get dataset info and check model
        datasets_info = {}
        
        client = Client()
        # The kind for the new entity
        kind = GROUPNAME
        # The Cloud Datastore key for the new entity
        key = client.key(kind, "datasets")
        try:
            task = client.get(key)
            # no datasets saved
            if task:
                datasets_info = task
        except Exception:
            abort(400)

        # is model in the dataset meta
        if jsondata["dataset"] not in datasets_info:
            abort(400)
        dataset_info = datasets_info[jsondata["dataset"]]
        if "transfer" not in dataset_info:
            abort(400)
        if jsondata["model_name"] not in dataset_info["transfer"]:
            abort(400)
        dataset_source = dataset_info["location"]

        # create random meta
        # write to google bucket
        storage_client = storage.Client()
        bucket = storage_client.bucket(TRANSFER_DEST)

        # create random name
        letters = string.ascii_lowercase
        random_dir = ''.join(random.choice(letters) for i in range(20))

        # write config
        tsize = [256,256,256]
        config = {
                        "@type" : "neuroglancer_multiscale_volume",
                        "data_type" : "uint8",
                        "num_channels" : 1,
                        "scales" : [
                            {
                                "chunk_sizes" : [
                                    [ 64, 64, 64 ]
                                    ],
                                "encoding" : "raw",
                                "key" : "8.0x8.0x8.0",
                                "resolution" : [ 8,8,8 ],
                                "size" : [ tsize[0], tsize[1], tsize[2] ],
                                "offset": [0, 0, 0]
                            }
                        ],
                        "type" : "image"
                    }
        blob = bucket.blob(random_dir + "/info")
        blob.upload_from_string(json.dumps(config))
        dest = TRANSFER_DEST + "/" + random_dir + "/8.0x8.0x8.0"

        # handle auth
        # Set up metadata server request
        # See https://cloud.google.com/compute/docs/instances/verifying-instance-identity#request_signature
        metadata_server_token_url = 'http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience='

        token_request_url = metadata_server_token_url + TRANSFER_FUNC
        token_request_headers = {'Metadata-Flavor': 'Google'}

        # Fetch the token
        token_response = requests2.get(token_request_url, headers=token_request_headers)
        jwt = token_response.content.decode("utf-8")

        headers = {}
        headers["Content-type"] = "application/json" 
        # Provide the token in the request to the receiving service
        headers["Authorization"] = f"Bearer {jwt}"

        # create request config template (start is custom for each job)
        tpsize = [128,128,128]
        config_cr = {
                "location": dataset_source,
                "glbstart": [jsondata["center"][0] - tsize[0]//2, jsondata["center"][1] - tsize[1]//2, jsondata["center"][2] - tsize[2]//2],
                "size": tpsize,
                "model_name": jsondata["model_name"],
                "dest": dest
        }

        # thread (up to 64) call to cloud run
        NUM_THREADS = 8
        def call_cr(thread_id):
            num = 0
            for ziter in range(0, tsize[2], 128):
                for yiter in range(0, tsize[1], 128):
                    for xiter in range(0, tsize[0], 128):
                        num += 1
                        if num % NUM_THREADS != thread_id:
                            continue
                        config_temp = config_cr.copy()
                        base = config_temp["glbstart"]
                        config_temp["start"] = [base[0]+xiter, base[1]+yiter, base[2]+ziter]
                        # occaaional errors are not critically important 
                        retries = 10
                        while retries > 0:
                            resp = requests2.post(TRANSFER_FUNC, data=json.dumps(config_temp), headers=headers)
                            if resp.status_code != 200:
                                retries -= 1
                                time.sleep(5)
                            else:
                                break

        threads = [threading.Thread(target=call_cr, args=(thread_id,)) for thread_id in range(NUM_THREADS)]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # return address
        return json.dumps({"addr": f"https://neuroglancer-demo.appspot.com/#!%7B%22layers%22%3A%5B%7B%22type%22%3A%22image%22%2C%22source%22%3A%7B%22url%22%3A%22precomputed%3A%2F%2Fgs%3A%2F%2F{TRANSFER_DEST}%2F{random_dir}%22%7D%2C%22tab%22%3A%22source%22%2C%22name%22%3A%22jpeg%22%7D%5D%2C%22selectedLayer%22%3A%7B%22layer%22%3A%22jpeg%22%2C%22visible%22%3Atrue%7D%7D"})
    except Exception as e:
        return make_response(traceback.format_exc(), 400)

def handlerAtlas(email, dataset, point, jsondata, method):
    """Enables annotations for a dataset.
    
    Data is stored indexed uniquely to an x,y,z.  Post
    should only be one synapse at a time.  The json payload
    is arbitrary.
    """

    # TODO: add dataset-specific GET 

    roles = get_roles(email, dataset)
    if "clio_general" not in roles:
        abort(403)

    if (method == "POST" or method == "DELETE") and ("clio_write" not in roles):
        abort(403)

    # Instantiates a client
    client = Client()
    # The kind for the new entity
    kind = GROUPNAME
    # The Cloud Datastore key for the new entity
    key = client.key(kind, "atlas")

    if method == "GET":
        try:
            task = client.get(key)
            # no annotations saved
            if not task:
                if dataset == "all":
                    return json.dumps([])
                else:
                    return json.dumps({})

            output = None
            if dataset == "all":
                output = []
                for _, val in task.items():
                    output.append(val)
            else:
                output = {}
                for _, val in task.items():
                    if val["dataset"] == dataset:
                        point_str = f'{val["location"][0]}_{val["location"][1]}_{val["location"][2]}'
                        output[point_str] = val
            
            return json.dumps(output)
        except Exception as e:
            abort(400)
    elif method == "POST" or method == "PUT":
        try:
            # check formaat
            if "title" not in jsondata:
                raise RuntimeError("not formatted properly")
            if "description" not in jsondata:
                raise RuntimeError("not formatted properly")
            if "user" not in jsondata:
                raise RuntimeError("not formatted properly")
            jsondata["timestamp"] = time.time()
            jsondata["dataset"] = dataset
            jsondata["location"] = [int(point[0]), int(point[1]), int(point[2])]

            with client.transaction():
                task = client.get(key)
                if not task:
                    task = Entity(key)
                point_str = dataset + ":" + str(point[0]) + "_" + str(point[1]) + "_" + str(point[2])
                payload = {}
                payload[point_str] = jsondata
                task.update(payload)
                client.put(task)
        except:
            abort(400)
    elif method == "DELETE":
        # info should be [ name1, name2, etc]
        try:
            with client.transaction():
                task = client.get(key)
                if not task:
                    abort(400)
                else:
                    point_str = dataset + ":" + str(point[0]) + "_" + str(point[1]) + "_" + str(point[2])
                    if point_str in task:
                        del task[point_str]
                client.put(task)
        except Exception as e:
            print(e)
            abort(400)
    else:
        abort(400)

    return ""


def handlerAnnotations(email, dataset, point, jsondata, method):
    """Enables annotations for a dataset.
    
    Data is stored indexed uniquely to an x,y,z.  Post
    should only be one synapse at a time.  The json payload
    is arbitrary.
    """
   
    roles = get_roles(email, dataset)
    if "clio_general" not in roles:
        return abort(403)

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
            abort(400)
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
            abort(400)
    elif method == "DELETE":
        # info should be [ name1, name2, etc]
        try:
            with client.transaction():
                task = client.get(key)
                if not task:
                    abort(400)
                else:
                    point_str = str(point[0]) + "_" + str(point[1]) + "_" + str(point[2])
                    if point_str in task:
                        del task[point_str]
                client.put(task)
        except Exception as e:
            print(e)
            abort(400)
    else:
        abort(400)

    return ""

def handlerDatasets(email, dataset_info, method):
    """Manages dataset information.

    format:
    {name: [desc, location], name2: ... }

    Indexing is done on dataset name.  Multiple datasets
    can be added or deleted using the API.

    dataset_info is empty for a GET, is a diction
    for a POST, and is a list of datasets for a DELETE.
    """
   
    roles = get_roles(email)

    # TODO: look at per dataset auth

    if "clio_general" not in roles:
        abort(403)

    if (method == "POST" or method == "DELETE" or method == "PUT") and "admin" not in roles:
        abort(403)

    db = firestore.Client()

    if method == "GET":
        try:
            datasets = db.collection(CLIO_DATASETS).get()
            datasets_out = {}
            for dataset in datasets:
                datasets_out[dataset.id] = dataset.to_dict()
            return json.dumps(datasets_out)
        except Exception as e:
            print(e)
            abort(400)
    elif method == "POST" or method == "PUT":
        try:
            for dataset, data in dataset_info.items():
                db.collection(CLIO_DATASETS).document(dataset).set(data)
        except Exception as e:
            print(e)
            abort(400)
    elif method == "DELETE":
        # info should be [ name1, name2, etc]
        try:
            for dataset in dataset_info:
                db.collection(CLIO_DATASETS).document(dataset).delete()
        except Exception as e:
            print(e)
            abort(400)
    else:
        abort(400)

    return ""

def handlerUsers(email, userdata, method):
    global USER_CACHE
    
    roles = get_roles(email)
    # allow admin to have access
    if "admin" not in roles:
        abort(403)

    db = firestore.Client()

    if method == "GET":
        try:
            all_users = db.collection(CLIO_USERS).get()
            user_out = {}
            for user in all_users:
                user_out[user.id] = user.to_dict()
            return json.dumps(user_out)
        except Exception as e:
            print(e)
            abort(400)
    elif method == "POST" or method == "PUT":
        # add / replace user data
        try:
            # update on uesr at a time
            for user, data in userdata.items():
                db.collection(CLIO_USERS).document(user).set(data)
                USER_CACHE[user] = data
        except Exception as e:
            print(e)
            abort(400)
    elif method == "DELETE":
        try:
            for user in userdata:
                db.collection(CLIO_USERS).document(user).delete()
                del USER_CACHE[user]
        except Exception as e:
            print(e)
            abort(400)
    else:
        abort(400)

    return ""

def get_auth_email(token):
    """Retrieve the email associated with token.

    Throws exception if token is invalid.
    """
    idinfo = id_token.verify_oauth2_token(token, requests.Request()) 
   
    # grab lower-case version of email
    return idinfo["email"].lower()

def get_roles(email, dataset=""):
    """Check google token and return user roles.
    """
    global USER_CACHE
    
    # TODO: auto refresh if cache is >10 minutes old

    roles = set()
    if email == OWNER:
        roles.add("admin")
    if email not in USER_CACHE:
        db = firestore.Client()
        data = db.collection(CLIO_USERS).document(email).get()
        data = data.to_dict()
        if data is None:
            data = {}
        USER_CACHE[email] = data 
    
    auth_data = USER_CACHE[email]

    if "clio_global" in auth_data:
        roles = roles.union(auth_data["clio_global"])
    if "datasets" in auth_data and dataset in auth_data["datasets"]:
        roles =  roles.union(auth_data["datasets"][dataset])

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

def getSignature(email, dataset, point):
    roles = get_roles(email, dataset)
    if "clio_general" not in roles:
        abort(403)

    try:
        pt, sig = fetch_signature(dataset, *point)
        res = {"point": pt, "signature": str(sig)}
    except Exception as e:
        res = {"messsage": str(e)}
    return json.dumps(res)

def getMatches(email, dataset, point):
    roles = get_roles(email, dataset)
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
        abort(401)
    authlist = auth.split(' ')
    if len(authlist) != 2:
        abort(401) # Bearer must be specified
    auth = authlist[1]

    # check user auth and populate cache
    email = "" 
    try:
        email = get_auth_email(auth)
    except Exception as e:
        print(e)
        abort(401)

    pathinfo = request.path.strip("/")
    urlparts = pathinfo.split('/')

    if len(urlparts) == 0:
        abort(400)

    # if data is posted it should be in JSON format
    jsondata = request.get_json(force=True, silent=True)
    
    # GET/POST/DELETE dataset information
    if urlparts[0] == "datasets":
        resp = handlerDatasets(email, jsondata, request.method)
    # GET/POST/PUT/DELETE /annotations/[dataset]?x=X,y=Y,z=Z
    elif urlparts[0] == "annotations" and len(urlparts) == 2:
        dataset = urlparts[1]
        # not necessary for a GET request
        x = request.args.get('x')
        y = request.args.get('y')
        z = request.args.get('z')
        resp = handlerAnnotations(email, dataset, (x,y,z), jsondata, request.method)
    elif urlparts[0] == "atlas" and len(urlparts) == 2:
        """Similar to 'annotataions' with the following exceptions.
        
        Posted JSON must have the following format:

        * title
        * description
        * user

        A 'timestamp' is automatically added as seconds from epoch.

        Also, a GET request with the dataset name 'all' will return
        all annotations and a new field for 'dataset' and 'location'.
        """
        dataset = urlparts[1]
        # not necessary for a GET request
        x = request.args.get('x')
        y = request.args.get('y')
        z = request.args.get('z')
        resp = handlerAtlas(email, dataset, (x,y,z), jsondata, request.method)
    # GET /users -- return all users and auth (admin)
    # POST /users -- add user and auth
    elif urlparts[0] == "users":
        resp = handlerUsers(email, jsondata, request.method) 
    elif urlparts[0] == "roles":
        _ = get_roles(email)
        resp = json.dumps(USER_CACHE[email])
    elif urlparts[0] == "transfer":
        resp = transferData(email, jsondata)
    elif urlparts[0] == "signatures" and len(urlparts) == 3 and urlparts[1] == "atlocation":
        dataset = urlparts[2]
        # not necessary for a GET request
        x = int(request.args.get('x'))
        y = int(request.args.get('y'))
        z = int(request.args.get('z'))
        resp = getSignature(email, dataset, (x,y,z))
    elif urlparts[0] == "signatures" and len(urlparts) == 3 and urlparts[1] == "likelocation":
        dataset = urlparts[2]
        # not necessary for a GET request
        x = int(request.args.get('x'))
        y = int(request.args.get('y'))
        z = int(request.args.get('z'))
        resp = getMatches(email, dataset, (x,y,z))
    else:
        abort(400)

    # make response 
    if type(resp) == str:
        resp = make_response(resp)
        
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    resp.headers['Access-Control-Allow-Methods'] = 'POST, GET, DELETE, OPTIONS'
    return resp

