import os
import detect_random


dir = os.path.dirname(os.path.realpath(__file__))
exclude = ["x86_64-linux-gnu","apache2"]

def checkString(str):
    
    # intializing flag variable
    flag_l = False
    flag_n = False
      
    # checking for letter and numbers in 
    # given string
    for i in str:
        
        # if string has letter
        if i.isalpha():
            flag_l = True
  
        # if string has number
        if i.isdigit():
            flag_n = True
      
    # returning and of flag
    # for checking required condition
    return flag_l and flag_n

def filterTarget(path):
    #s = ''
    dirs = path.split('/')
    dirs[-1] = dirs[-1].split(' ')[0]
    #if not any(substring in path for substring in exclude):
    for ele in dirs:
        if checkString(ele):
            #s = s + str(ele) + '\n'
            return path.split(' ')[0]
    return None

def pathProcessor(path):
    str = ''
    path = path.split('/')
    path[-1] = path[-1].split(' ')[0]
    for index, ele in enumerate(path):
        if detect_random.randomFileDetector(None, "model.pki", ele) == False and ele.isalpha() == False and ele not in exclude and '.so' not in ele:
            if index == len(path) - 1:
                path[index] = '**'
            else:
                path[index] = '*'
        elif ele.isnumeric() == True:
            if index == len(path) - 1:
                path[index] = '**'
            else:
                path[index] = '*'
    for index, ele in enumerate(path):
        if index != len(path) - 1:
            str = str + ele + '/'
        else:
            str = str + ele
    return str

def initDetector(data, output, check):
    detect_random.randomFileDetector(data, output, check)

def main():
    fileHave = set()
    # file to save the final result
    data_file = open(dir + "/result", "w")
    #file to save all matched random file paths
    raw_path = open(dir + "/raw_path", "w")
    #file to save all matched random file paths after globbing
    globbing_path = open(dir + "/globbing_path", "w")
    #file to save all normal fixed file paths
    fixed_path = open(dir + "/fixed_path", "w")
    initDetector("words.txt", "model.pki", None)  
    with open(dir + "/file_rule_default_wordpress.txt") as file:
    #with open(dir + "/test_rules") as file:
        for line in file:
            path = filterTarget(line)
            if path:
                raw_path.write(path + os.linesep)
                path = pathProcessor(path)
                globbing_path.write(path + os.linesep)
            else:
                path = line.split(' ')[0]
                fixed_path.write(path + os.linesep)
            if path not in fileHave:
                data_file.write(path + os.linesep)
                fileHave.add(path)

if  __name__ == "__main__":
    main()
