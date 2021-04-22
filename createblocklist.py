#This script is to create host file for blocking ads
#This script will grab host files from the sources file,
#download them and merge them in to single file for DNS adblocking


import sys
import urllib.request
import subprocess
import hashlib
import zipfile
import os
import tarfile


#header for the request body
headers = { 'User-Agent' : 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.6) Gecko/20070802 SeaMonkey/1.1.4' }

#remove duplicate domains
def deDupBlockList():
    
    block_list_dict = {}
    dedup_block_list = ""
    writeToFile("tempremoveurls", dedup_block_list)
    i = 0
    data = readFile("tempblocklist")
    data = filter(None, data.split('\n'))
    for host in data:
        if host.startswith("www."):
            host = host.replace("www.", "")
        block_list_dict[host] = 0
        i = i + 1


    print(f"De-dupping {str(i)} URLs. This may take some time...Hang on!!!")

    i = 0

    for host in data:
        if host.startswith("www."):
            host = host.replace("www.","")  #simplify the search
        if not subUrlInDict(block_list_dict, host) and not isIpAddr(host):
            #if not in the list add
            dedup_block_list = dedup_block_list + "\n" + host
        
        i = i + 1
        if i > 10000:
            i = 0
            sys.stdout.write('.')
            sys.stdout.flush()
            addToFile("tempremoveurls", dedup_block_list)
            dedup_block_list = "\n"

    addToFile("tempremoveurls", dedup_block_list)

    print("Writing final blocklist ")
    
    process = subprocess.Popen('sort -u tempblocklist > blocklist',
                         shell=True, stdout=subprocess.PIPE)

    process.communicate()


#download source host files
#if not found take the default one

def downloadSources(sources):

    data = ""

    for line in sources.splitlines():

        if not line.startswith("#") and len(line) > 1:
            data = ''

            try:
                req = urllib.request.Request(line, None, headers)
                data = urllib.request.urlopen(req).read()

                if line.endswith(".zip") or line.endswith(".gz"):
                    print("Got Zip", line)
                    data = unzipData(data, line)
                    sourcehash = "source-adult" + hashlib.md5(line.encode()).hexdigest()[:8]
                else:
                    #print('Else')
                    res = bytes(line, 'utf-8')
                    #print(type(res))
                    hash = hashlib.md5(res).hexdigest()[:8]
                    #print(hash)
                    sourcehash = "source-" + str(hash)
                    #print(sourcehash)
                
                #print('Out of else')
                print(type(data))
                data = data.decode('utf-8')
                data = data.replace('127.0.0.1', '')
                data = data.replace('0.0.0.0', '')
                data = data.replace("\r", "\n")
                data = data.replace("\t", "")
                data = data.replace(" ", "")
                #print(f"Downloaded {line} saving data to file {sourcehash}")
                #print('Before write')
                writeToFile(sourcehash, data)
                #print('After write')
            except urllib.request.URLError as err:
                print(err)
                print(line)
            except Exception as e:
                print(e)
                print("Bad Source for line", line)

def writeToFile(filename, data):
    target = open(filename,'w')
    target.truncate()
    target.write(data)
    target.close()

def addToFile(filename, data):
    target = open(filename, 'a')
    target.write(data)
    target.close()

def readFile(filename):
    target = open(filename, 'r')
    data = target.read()
    target.close()
    return data

def unzipData(data, line):

    if line.endswith(".zip"):
        writeToFile("tempzipdata.zip", data)
        file = zipfile.ZipFile("tempzipdata.zip", "r")
        for name in file.namelist():
            # ignore duplicate names
            data = file.read(name)
            os.remove("tempzipdata.zip")
            return data
    
    if line.endswith(".gz"):
        writeToFile("tempzipdata.tar.gz", data)
        t = tarfile.open('tempzipdata.tar.gz', 'r:gz')
        print(t.getnames())
        print(t.getmembers())
        for member in t.getmembers():
            print(member.name)
            if member.name == "adult/domains":
                try:
                    f = t.extractfile(member.name)
                except KeyError:
                    print(f"ERROR: Did not find in tar archive")
                else:
                    print(member.name)
                    #ignore duplicate names
                    data = f.read()
                    os.remove("tempzipdata.tar.gz")
                    return data



#take all the sources and remove the duplicates and merge into a single file
def mergeSources():

    print('Merging Ads')
    process = subprocess.Popen('sort -u source-* | grep -v "#" | grep -v "localhost" | grep -v "broadcasthost"  > tempblocklist',
                               shell=True, stdout=subprocess.PIPE)
    
    #wait until Popen to finish
    process.communicate()

#load the block list into the dictionary
# def loadBlockList(filename):
#     i = 0
#     data = readFile(filename)
#     data = filter(None, data.split('\n'))
#     for line in data:
#         BlockListDict[line] = 0
#         i = i + 1
    
#     print(f"Loaded {str(i)} urls to block ")


def subUrlInDict(block_list_dict, host):
    ittr = host.count('.')
    if ittr > 1:
        temp, host = host.split(".", 1)
        ittr = ittr - 1
        while ittr > 1:
            if block_list_dict.get(host) is not None:
                return True
            temp, host = host.split('.',1)
            ittr = ittr - 1
    return False

def isIpAddr(host):
    split_count = host.split('.')
    if len(split_count) != 4:
        return False
    try:
        return all(0<=int(p)<256 for p in split_count)
    except ValueError:
        return False




def cleanUp():
    #clean unwanted or duplicate files
    #os.remove("tempremoveurls")
    #os.remove("tempblocklist")
    pass

def main(argv):

    downloadSources(readFile("sources"))
    mergeSources()
    deDupBlockList()
    cleanUp()

if __name__ == "__main__":
    main(sys.argv[1:])
    print("Done!!!")            