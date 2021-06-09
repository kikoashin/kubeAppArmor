import os
import json

#change a dict to class
class Glob_Patterns():
    def __init__(self, glob_dict):
        self.__dict__ = glob_dict

glob_patterns = None
if not glob_patterns:
    rule_engine_dir = os.path.dirname(os.path.realpath(__file__))
    with open(rule_engine_dir + "/glob_patterns_rules.json") as gb_file:
        glob_dict = json.load(gb_file)
    glob_patterns = Glob_Patterns(glob_dict)

def genSpecAccessPath(series):
    for (regex, sub_value) in glob_patterns.container_special_access_paths.items():
        series = series.str.replace(regex, sub_value)
    return series 

def genGlobalAccessPath(series):
    for (regex, sub_value) in glob_patterns.glob_patterns_regex.items():
        series = series.str.replace(regex, sub_value)
    return series

def genFullAccessPath(series):
    for path in glob_patterns.container_full_access_paths:
        series = series.str.replace(path + ".+", path + "**")
    return series



