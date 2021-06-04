from elasticsearch import Elasticsearch
import numpy as np
import pandas
import json


es = Elasticsearch()
total_docs = 8000
no_use_keys = ["laddr", "faddr", "lport", "fport", "addr"]
doc = {
    "query": {
        "bool": {
            "must": [
                {
                    "exists": {
                        "field": "body.sock_type"
                    }
                },
                {
                    "match": {
                        "body.profile": "docker_flaskapp"
                    }
                }                
            ]
        }
    }
}
""" doc = {
    "query": {
        "match_all": {}
    }
} """
res = es.search(index="fluentd", size=total_docs, body=doc)

# declare a new list for the Elasticsearch documents
# nested inside the API response object
elastic_docs = res["hits"]["hits"]

# empty dict
fields = {}
for num, doc in enumerate(elastic_docs):
    # body_data: dict
    body_data = doc["_source"]["body"]
    for key, val in body_data.items():
        if key not in no_use_keys:
            # the first key is not existed in field so KeyError comes, so we need to create an array
            try:
                fields[key] = np.append(fields[key], val)
            except KeyError:
                fields[key] = np.array([val])

""" for key, val in fields.items():
    print (key, "--->", val)
    print ("NumPy array len:", len(val), "\n") """

elastic_df = pandas.DataFrame(fields)
elastic_df = elastic_df.drop_duplicates(subset=['sock_type', 'family', 'protocol'])
print ('elastic_df:', type(elastic_df), "\n")
print (elastic_df) # print out the DF object's contents
# print number of documents
# print ("documents returned:", len(res["hits"]["hits"]))



#network rules:
#NETWORK RULE = [ QUALIFIERS ] 'network' [ DOMAIN ] [ TYPE | PROTOCOL ]
#[DOMAIN] -> "family"
#[ TYPE | PROTOCOL ] -> "sock_type","protocol(6:tcp,17:udp)"