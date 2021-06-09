from elasticsearch import Elasticsearch
import numpy as np
import pandas
import glob_rules

#The from parameter defines the offset from the first result you want to fetch. 
#The size parameter allows you to configure the maximum amount of hits to be returned.
es = Elasticsearch()
total_docs = 10000
#profile_name = "docker_redis"
profile_name = "docker_flaskapp"


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
    #print("scroll_id is: ", sid)
    elastic_docs = res["hits"]["hits"]
    # get the size of the first scroll
    scroll_size = len(elastic_docs)
    #print("scroll_size is: ", scroll_size)
    # empty dict
    fields = {}
    while scroll_size > 0:
        #print("scrolling......")
        fields = processHits(elastic_docs, no_use_keys, fields)
        res = es.scroll(scroll_id=sid, scroll='5s')
        # Update the scroll ID
        sid = res['_scroll_id']
        #print("new scroll_id is: ", sid)
        elastic_docs = res["hits"]["hits"]
        # Get the number of results that returned in the last scroll
        scroll_size = len(elastic_docs)
        #print("scroll_size is: ", scroll_size)
    elastic_df = pandas.DataFrame(fields)
    elastic_df = elastic_df.drop_duplicates(subset)
    for column in elastic_df:
        elastic_df[column] = elastic_df[column].str.replace('"', "")
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
                            "body.profile": profile_name
                        }
                    }                
                ]
            }
        }
    }
    no_use_keys = ["laddr", "faddr", "lport", "fport", "addr"]
    subset = ["family","sock_type", "protocol"]
    df_net = filter(doc, subset, no_use_keys, es)
    if not df_net.empty:
        df_net['rule'] = 'network ' + df_net[['family', 'sock_type']].agg(" ".join, axis=1).astype(str) + ','
        return df_net['rule'], True
    else:
        return None, False

#file access rules:
#FILE RULE = [ QUALIFIERS ] [ 'owner' ] ( 'file' | [ 'file' ] ( FILEGLOB ACCESS  | ACCESS FILEGLOB ) [ '->' EXEC TARGET ] )
#FILEGLOB -> name
#ACCESS -> requested_mask
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
                            "body.profile": profile_name
                        }
                    }                
                ]
            }
        }
    }
    no_use_keys = ["info", "target"]
    subset = ["name","requested_mask"]
    df_file = filter(doc, subset, no_use_keys, es)
    #replace global patterns

    if not df_file.empty:
        #print("df_file is: \n", df_file)
        df_file['name'] = glob_rules.genSpecAccessPath(df_file['name'])
        df_file['name'] = glob_rules.genGlobalAccessPath(df_file['name'])
        df_file['name'] = glob_rules.genFullAccessPath(df_file['name'])
        df_file['rule'] = df_file[['name', 'requested_mask']].agg(" ".join, axis=1).astype(str) + ','
        df_file = df_file.drop_duplicates(subset=["rule"])
        df_file.to_csv("test.txt", columns=["rule"], header=False, index=False)
        return df_file['rule'], True
    else:
        return None, False
    
#capability rules
#CAPABILITY RULE = [ QUALIFIERS ] 'capability' [ CAPABILITY LIST ]
#CAPABILITY -> capname
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
                            "body.profile": profile_name
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
    df_cap = filter(doc, subset, no_use_keys, es)
    if not df_cap.empty:
        df_cap['rule'] = 'capability ' + df_cap['capname'].astype(str) + ','
        return df_cap['rule'], True
    else:
        return None, False

def main():
    """ net_rule, net_flag = netRuleGenerator(es)
    if net_flag:
        print("network access policies are:\n", net_rule)
    else:
        print("no network access found from the logs") """

    file_rule, file_flag = fileRuleGenerator(es)
    if file_flag:
        print("file acccess policies are:\n", file_rule)
    else:
        print("no file acccess found from the logs")    

    #df_file.to_csv("test.txt", columns=["rule"], header=False, index=False)
    #print(type(df_file['rule'][0]))

    """ cap_rule, cap_flag = capRuleGenerator(es)
    if cap_flag:
        print("capability policies are:\n", cap_rule)
    else:
        print("no capability found from the logs") """
    


if __name__ == "__main__":
    main()
