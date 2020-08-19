# Cloud function for managing Clio

Simple cloud function for managing logins, datasets, and other resources useful
for analyzing and using large electron microscopy (EM) datasets.

The service uses Google Oauth and maintains authorization data inside
Google's datastore.  

## Installation

The function can be installed by copying the python and requirements file
into a Google Cloud function environment.  An "OWNER" environment
variaable should be specified as an email address.
If signature searching is supported, "SIG_BUCKET" should
be set to the location of google storaage bucket containing
the dataset signatures.

## API

### datasets

Datasets are stored in a dictionary where the key is a unique dataset name and the value is the description
and location of the dataset.

Post datasets (can post multiple, will overwrite pre-existing):
	
	% curl -X  POST -H "Content-Type: application/json"  --header "Authorization: Bearer $(gcloud auth print-identity-token)" https://us-east4-flyem-private.cloudfunctions.net/clio_toplevel/datasets -d '{"mb20": { "description": "4nm MB", "location": "gs://"}}'

Get datasets:
	
	% curl -X GET -H "Content-Type: application/json"  --header "Authorization: Bearer $(gcloud auth print-identity-token)" https://us-east4-flyem-private.cloudfunctions.net/clio_toplevel/datasets 

Delete datasets:
	
	% curl -X  DELETE -H "Content-Type: application/json"  --header "Authorization: Bearer $(gcloud auth print-identity-token)" https://us-east4-flyem-private.cloudfunctions.net/clio_toplevel/datasets -d '["mb20"]'

### annotations

Annotations are stored in a dictionary where the key is a unique x_y_z string and the value is whatever dictionary
payload that is provided by the application.  Annotations are unique per dataset.  Annotation retrieval returns
every annotation, so this is not designed for 10s of thousands of annotations.  In the example below, "mb20"
is the name of the dataset.

Post annotation (only one at a time, will overwrite pre-existing):
	
	% curl -X  POST -H "Content-Type: application/json"  --header "Authorization: Bearer $(gcloud auth print-identity-token)" https://us-east4-flyem-private.cloudfunctions.net/clio_toplevel/annotations/mb20?x=50\&y=30\&z=50 -d '{"foo": "bar"}'

Get annotations:
	
	% curl -X GET -H "Content-Type: application/json"  --header "Authorization: Bearer $(gcloud auth print-identity-token)" https://us-east4-flyem-private.cloudfunctions.net/clio_toplevel/annotations/mb20

Delete annotations (only one at a time):

	curl -X  DELETE -H "Content-Type: application/json"  --header "Authorization: Bearer $(gcloud auth print-identity-token)" https://us-east4-flyem-private.cloudfunctions.net/clio_toplevel/annotations/mb20?x=50\&y=30\&z=50

### searching image dataset using signatures

If signatures are computed for a dataset, one can query the signature closest to a given point or find a set of locations similar to the signature found at a given point. 

Find signature near a given point:

	% curl -X GET -H "Content-Type: application/json"  --header "Authorization: Bearer $(gcloud auth print-identity-token)" https://us-east4-flyem-private.cloudfunctions.net/clio_toplevel/signatures/atlocation/mb20?x=18416\&y=16369\&z=26467

Find matching points for a signature near a given point:

	% curl -X GET -H "Content-Type: application/json"  --header "Authorization: Bearer $(gcloud auth print-identity-token)" https://us-east4-flyem-private.cloudfunctions.net/clio_toplevel/signatures/likelocation/mb20?x=18416\&y=16369\&z=26467



### user management

Admins and the owner can retrieve a list of users, update roles and add new users, and delete users.

Add new user(s) or update roles (roles must be a list):
	
	% curl -X POST -H "Content-Type: application/json"  --header "Authorization: Bearer $(gcloud auth print-identity-token)" https://us-east4-flyem-private.cloudfunctions.net/clio_toplevel/users -d '{"foobar@gmail.com": ["admin", "clio_general" ]}'

Remove user(s):
	
	curl -X DELETE -H "Content-Type: application/json"  --header "Authorization: Bearer $(gcloud auth print-identity-token)" https://us-east4-flyem-private.cloudfunctions.net/clio_toplevel/users -d '["plaza.stephen"]'

Retrieve users:
	
	% curl -X GET -H "Content-Type: application/json"  --header "Authorization: Bearer $(gcloud auth print-identity-token)" https://us-east4-flyem-private.cloudfunctions.net/clio_toplevel/users

### for applications using this for auth

This service can be used to authorize different applications provided that specified roles have been added
to the user's authorization.  If a user is not on any of the auth lists, they will be given the role of "noauth". 

Determine the roles granted to: the users:

	$ curl -X GET -H "Content-Type: application/json"  --header "Authorization: Bearer $(gcloud auth print-identity-token)" https://us-east4-flyem-private.cloudfunctions.net/clio_toplevel/roles







