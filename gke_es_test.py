from elasticsearch import Elasticsearch, helpers
from pandas import json_normalize
import glob_rules
import analyzer
import time
import collections
import os


#connect to the elasticsearch running on loaclhost
es = Elasticsearch()
total_docs = 10000

#the AppArmor profile name
profile_name = "default_wordpress"

#search target logs from elasticsearch and transfrom them to dataframe object
def filter(doc, subset, es):
    response = helpers.scan(es, index="logstash-2021.06.*", size=total_docs, query=doc, scroll='10m')
    output_all = collections.deque()
    output_all.extend(response)
    output_df = json_normalize(output_all)
    output_df = output_df[[x for x in output_df.columns if "_source." in x]]
    output_df = output_df.drop_duplicates(subset)
    for column in output_df:
        output_df[column] = output_df[column].str.replace('"', "")
    print (output_df) # print out the DF object's contents
    return output_df

    
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
                            "field": "audit_field_capability"
                        }
                    },
                    {
                        "match": {
                            "audit_field_profile": profile_name
                        }
                    },
                    {
                        "match": {
                            "audit_field_operation": "capable"
                        }
                    },
                    {
                        "match": {
                            "audit_field_apparmor": "AUDIT"
                        }
                    }                  
                ]
            }
        }
    }
    subset = ["_source.audit_field_capname"]
    start = time.time()
    df_cap = filter(doc, subset, es)
    end = time.time()
    print("use {} to generate original rules for capabilities".format(end - start))
    if not df_cap.empty:
        df_cap['rule'] = 'capability ' + df_cap['_source.audit_field_capname'].astype(str) + ','
        df_cap.to_csv("cap_rule_{}.txt".format(profile_name), columns=["rule"], header=False, index=False)
        print("capability policies are:\n", df_cap['rule'])  
    else:
        print("no capability found from the logs")


#network rules:
#NETWORK RULE = [ QUALIFIERS ] 'network' [ DOMAIN ] [ TYPE | PROTOCOL ]
#[DOMAIN] -> "family"
#[ TYPE | PROTOCOL ] -> "sock_type","protocol(6:tcp,17:udp)"
def netRuleGenerator(es):
    subset = ["_source.audit_field_family","_source.audit_field_sock_type", "_source.audit_field_protocol"]
    #network operations has two formats, with and without "lport,laddr,fport,faddr", so two "doc" should be defined.
    doc_net_type1 =  {
        "query": {
            "bool": {
                "must": [
                    {
                        "exists": {
                            "field": "audit_field_sock_type"
                        }
                    },
                    {
                        "match": {
                            "audit_field_profile": profile_name
                        }
                    },
                    {
                        "match": {
                            "audit_field_apparmor": "AUDIT"
                        }
                    }               
                ],
                "must_not": [
                    {
                        "exists": {
                            "field": "audit_field_laddr"
                        }
                    },
                    {
                        "exists": {
                            "field": "audit_field_lport"
                        }
                    },
                    {
                        "exists": {
                            "field": "audit_field_faddr"
                        }
                    },
                    {
                        "exists": {
                            "field": "audit_field_fport"
                        }
                    }                  
                ],              
            }
        }
    }
    doc_net_type2 =  {
        "query": {
            "bool": {
                "must": [
                    {
                        "exists": {
                            "field": "audit_field_sock_type"
                        }
                    },
                    {
                        "match": {
                            "audit_field_profile": profile_name
                        }
                    },
                    {
                        "match": {
                            "audit_field_apparmor": "AUDIT"
                        }
                    },
                    {
                        "exists": {
                            "field": "audit_field_laddr"
                        }
                    },
                    {
                        "exists": {
                            "field": "audit_field_lport"
                        }
                    },
                    {
                        "exists": {
                            "field": "audit_field_faddr"
                        }
                    },
                    {
                        "exists": {
                            "field": "audit_field_fport"
                        }
                    }             
                ],            
            }
        }
    } 
    df_net_type1 = filter(doc_net_type1, subset, es)
    if not df_net_type1.empty:
        df_net_type1['rule'] = 'network ' + df_net_type1[['_source.audit_field_family', '_source.audit_field_sock_type']].agg(" ".join, axis=1).astype(str) + ','

        df_net_type1.to_csv("net_rule_{}.txt".format(profile_name), columns=["rule"], mode='w', header=False, index=False)
        print("network access type1 policies are:\n", df_net_type1['rule'])
    else:
        print("no network access type1 found from the logs")
    df_net_type2 = filter(doc_net_type2, subset, es)
    if not df_net_type2.empty:
        df_net_type2['rule'] = 'network ' + df_net_type2[['_source.audit_field_family', '_source.audit_field_sock_type']].agg(" ".join, axis=1).astype(str) + ','
        df_net_type2.to_csv("net_rule_{}.txt".format(profile_name), columns=["rule"], mode='a', header=False, index=False)
        print("network access type2 policies are:\n", df_net_type2['rule'])
    else:
        print("no network access type2 found from the logs")


#replace paths with wild cards based on glob patterns
def globber(dfFile):
        dfFile['_source.audit_field_name'] = glob_rules.genSpecAccessPath(dfFile['_source.audit_field_name'])
        dfFile['_source.audit_field_name'] = glob_rules.genGlobalAccessPath(dfFile['_source.audit_field_name'])
        dfFile['_source.audit_field_name'] = glob_rules.genFullAccessPath(dfFile['_source.audit_field_name'])
        dfFile['_source.audit_field_name'] = glob_rules.genRandomFilePath(dfFile['_source.audit_field_name'])
        dfFile['_source.audit_field_requested_mask'] = glob_rules.genPermission(dfFile['_source.audit_field_requested_mask'])
        return dfFile

#file access rules:
#FILE RULE = [ QUALIFIERS ] [ 'owner' ] ( 'file' | [ 'file' ] ( FILEGLOB ACCESS  | ACCESS FILEGLOB ) [ '->' EXEC TARGET ] )
#FILEGLOB -> name
#ACCESS -> requested_mask
def fileAccessRuleGenerator(es):
    subset = ["_source.audit_field_name","_source.audit_field_requested_mask"]
    #execution operations have different format compared to other file accesses operations, so two "doc" should be defined.
    doc_file =  {
        "query": {
            "bool": {
                "must": [
                    {
                        "exists": {
                            "field": "fsuid"
                        }
                    },
                    {
                        "match": {
                            "audit_field_profile": profile_name
                        }
                    },
                    {
                        "match": {
                            "audit_field_apparmor": "AUDIT"
                        }
                    }               
                ],
                "must_not": [
                    {
                        "exists": {
                            "field": "audit_field_info"
                        }
                    },
                    {
                        "exists": {
                            "field": "audit_field_target"
                        }
                    }                   
                ],
                
            }
        }
    } 
    doc_file_exec =  {
        "query": {
            "bool": {
                "must": [
                    {
                        "exists": {
                            "field": "fsuid"
                        }
                    },
                    {
                        "match": {
                            "audit_field_profile": profile_name
                        }
                    },
                    {
                        "match": {
                            "audit_field_apparmor": "AUDIT"
                        }
                    },             
                    {
                        "exists": {
                            "field": "audit_field_info"
                        }
                    },
                    {
                        "exists": {
                            "field": "audit_field_target"
                        }
                    }                   
                ],               
            }
        }
    }
    df_file = filter(doc_file, subset, es)  
    if not df_file.empty:
        dfAfterGlobbing = globber(df_file)
        dfAfterGlobbing['rule'] = dfAfterGlobbing[['_source.audit_field_name', '_source.audit_field_requested_mask']].agg(" ".join, axis=1).astype(str) + ','
        dfAfterGlobbing = dfAfterGlobbing.drop_duplicates(subset=["rule"])
        dfAfterGlobbing.to_csv("file_rule_{}.txt".format(profile_name), columns=["rule"], mode='w', header=False, index=False)
        print("file acccess policies are:\n", dfAfterGlobbing['rule'])
    else:
        print("no file acccess found from the logs")

    df_file_exec = filter(doc_file_exec, subset, es)  
    if not df_file_exec.empty:
        dfExecAfterGlobbing = globber(df_file_exec)
        dfExecAfterGlobbing['_source.audit_field_info'] = dfExecAfterGlobbing['_source.audit_field_info'].str.replace(" fallback", "", regex=False)
        dfExecAfterGlobbing['rule'] = dfExecAfterGlobbing[['_source.audit_field_name', '_source.audit_field_info']].agg(" ".join, axis=1).astype(str) + ','
        dfExecAfterGlobbing = dfExecAfterGlobbing.drop_duplicates(subset=["rule"])
        dfExecAfterGlobbing.to_csv("file_rule_{}.txt".format(profile_name), columns=["rule"], mode='w', header=False, index=False)
        print("file exec policies are:\n", dfExecAfterGlobbing['rule'])
    else:
        print("no file exec found from the logs")

#process files with random names (combination of random numbers and letters)
def randomPathProcessor(profileName):
    fileHave = set()
    # file to save the final result
    data_file = open(dir + "/result", "w")
    #file to save all matched random file paths
    raw_path = open(dir + "/raw_path", "w")
    #file to save all matched random file paths after globbing
    globbing_path = open(dir + "/globbing_path", "w")
    #file to save all normal fixed file paths
    fixed_path = open(dir + "/fixed_path", "w")
    analyzer.initDetector("words.txt", "model.pki", None)  
    with open(dir + "/file_rule_{}.txt".format(profileName)) as file:
    #with open(dir + "/test_rules") as file:
        for line in file:
            path = analyzer.filterTarget(line)
            if path:
                raw_path.write(path + os.linesep)
                path = analyzer.pathProcessor(path)
                globbing_path.write(path + os.linesep)
            else:
                path = line.split(' ')[0]
                fixed_path.write(path + os.linesep)
            if path not in fileHave:
                data_file.write(path + os.linesep)
                fileHave.add(path)


def main():
    #network rule generation, generate file named with "net_rule_{profile_name}"
    netRuleGenerator(es)

    #file access rule generation, generate file named with "file_rule_{profile_name}"
    fileAccessRuleGenerator(es) 
    #process files with random names (combination of random numbers and letters)
    #generate three files named with "raw_path", "globbing_path", "fixed_path" and "result"
    randomPathProcessor(profile_name)

    #capability rule generation, generate file named with "cap_rule_{profile_name}"
    capRuleGenerator(es)
    

if __name__ == "__main__":
    main()
