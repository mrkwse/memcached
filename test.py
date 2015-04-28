from couchbase.bucket import Bucket
from couchbase.exceptions import CouchbaseError

c = Bucket('couchbase://192.168.106.101/hereherehere')

# doc['comment'] = "This is a test field"

try:
	result = c.insert("somedoc", {"test-field" : "test-body"})
	print result

except CouchbaseError as e:
	print "Couldn't set"
	raise
