from elasticsearch import Elasticsearch
import numpy as np
import pandas
import json

#The from parameter defines the offset from the first result you want to fetch. 
#The size parameter allows you to configure the maximum amount of hits to be returned.
es = Elasticsearch()
total_docs = 10000


""" doc = {
    "query": {
        "match_all": {}
    }
} """

def processHits(elastic_docs, no_use_keys, fields):
    # iterate over all hits
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
    #for key, val in fields.items():
        #print (key, "--->", val)
        #print ("NumPy array len:", len(val), "\n")
    return fields



def filter(doc, subset, no_use_keys, es):
    res = es.search(index="fluentd", size=total_docs, body=doc, scroll='5s')

    sid = res['_scroll_id']
    print("scroll_id is: ", sid)
    elastic_docs = res["hits"]["hits"]
    # get the size of the first scroll
    scroll_size = len(elastic_docs)
    print("scroll_size is: ", scroll_size)
    # empty dict
    fields = {}
    while scroll_size > 0:
        print("scrolling......")
        fields = processHits(elastic_docs, no_use_keys, fields)
        res = es.scroll(scroll_id=sid, scroll='5s')
        # Update the scroll ID
        sid = res['_scroll_id']
        print("new scroll_id is: ", sid)
        elastic_docs = res["hits"]["hits"]
        # Get the number of results that returned in the last scroll
        scroll_size = len(elastic_docs)
        print("scroll_size is: ", scroll_size)
    elastic_df = pandas.DataFrame(fields)
    elastic_df = elastic_df.drop_duplicates(subset)
    for column in elastic_df:
        elastic_df[column] = elastic_df[column].str.replace('"', "")
    print ('elastic_df:', type(elastic_df), "\n")
    #print (elastic_df) # print out the DF object's contents
    return elastic_df

#network rules:
#NETWORK RULE = [ QUALIFIERS ] 'network' [ DOMAIN ] [ TYPE | PROTOCOL ]
#[DOMAIN] -> "family"
#[ TYPE | PROTOCOL ] -> "sock_type","protocol(6:tcp,17:udp)"
def netRuleGenerator(es):
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
                            "body.profile": "docker_redis"
                        }
                    }                
                ]
            }
        }
    }
    no_use_keys = ["laddr", "faddr", "lport", "fport", "addr"]
    subset = ["family","sock_type", "protocol"]
    return filter(doc, subset, no_use_keys, es)

def fileRuleGenerator(es):
    doc =  {
        "query": {
            "bool": {
                "must": [
                    {
                        "exists": {
                            "field": "body.fsuid"
                        }
                    },
                    {
                        "match": {
                            "body.profile": "docker_redis"
                        }
                    }                
                ]
            }
        }
    }
    no_use_keys = ["info", "target"]
    subset = ["name","requested_mask"]
    return filter(doc, subset, no_use_keys, es)

def capRuleGenerator(es):
    doc =  {
        "query": {
            "bool": {
                "must": [
                    {
                        "exists": {
                            "field": "body.capability"
                        }
                    },
                    {
                        "match": {
                            "body.profile": "docker_redis"
                        }
                    },
                    {
                        "match": {
                            "body.operation": "capable"
                        }
                    }                 
                ]
            }
        }
    }
    no_use_keys = []
    subset = ["capname"]
    return filter(doc, subset, no_use_keys, es)

def main():
    #df_net = netRuleGenerator(es)
    #df_net['rule'] = df_net[['family', 'sock_type']].agg(" ".join, axis=1)
    #df_net['rule'] = 'network ' + df_net['rule'].astype(str) + ','
    #print(df_net)
    #df_file = fileRuleGenerator(es)
    #df_file['rule'] = df_file[['name', 'requested_mask']].agg(" ".join, axis=1)
    #print(df_file)
    #df_file.to_csv("test.txt", columns=["rule"], header=False, index=False)
    #print(type(df_file['rule'][0]))
    df_cap = capRuleGenerator(es)
    df_cap['rule'] = 'capability ' + df_cap['capname'].astype(str) + ','
    print(df_cap)


if __name__ == "__main__":
    main()
