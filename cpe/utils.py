from urllib3 import ProxyManager,PoolManager,disable_warnings ,exceptions as urllib3_exceptions
from shutil import copyfileobj
from zipfile import ZipFile
from os import path,remove,environ
try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET
try:
    from cPickle import load, PickleError, dump, HIGHEST_PROTOCOL
except ImportError:
    from pickle import load, PickleError, dump, HIGHEST_PROTOCOL
from .models import component, component_to_server
from products.models import server,product
from cve.tasks import add_vuln
import re
from vms.settings import USE_ELASTIC_SEARCH, ELASTIC_SEARCH_URL
from pkg_resources import parse_version

FEED_URL = 'http://nvd.nist.gov/feeds/xml/cpe/dictionary/'

class cpe_item:
    def __init__(self):
        self.name = ''
        self.title = ''
        self.ref = {}
        self.wfs = ''
        self.deprecated = False

    def __eq__(self,obj):
        return self.name == obj.name

    def __str__(self):
        return self.name

    def __ne__(self,obj):
        return self.name != obj.name

    def __hash__(self):
        return hash((self.name, self.title, self.wfs))

    def get_vendor(self):
        return self.wfs.split(':')[3]

    def get_product(self):
        return self.wfs.split(':')[4]

    def get_version(self):
        return self.wfs.split(':')[5]

    def get_update(self):
        return self.wfs.split(':')[6]

    def get_edition(self):
        return self.wfs.split(':')[7]

    def get_language(self):
        return self.wfs.split(':')[8]

    def get_sw_edition(self):
        return self.wfs.split(':')[9]

    def get_target_sw(self):
        return self.wfs.split(':')[10]

    def get_target_hw(self):
        return self.wfs.split(':')[11]

    def get_other(self):
        return self.wfs.split(':')[12]

APP_ROOT = path.dirname(path.abspath(__file__))
CACHE_PATH = path.join(APP_ROOT,'cache')

class cpe_handler:
    def __init__(self):
        self.cpe_dictionary_filename = path.join(CACHE_PATH,'official-cpe-dictionary_v2.3.xml')
        self.cpe_cache_filename = path.join(CACHE_PATH,'cpe_dictionary.db')
        self.cpe_names_filename = path.join(CACHE_PATH,'cpe_names.db')
        self.zipfile_location = path.join(CACHE_PATH,'xml.zip')
        self.meta_file_path = path.join(CACHE_PATH,'cpe.meta')


        if USE_ELASTIC_SEARCH:
            from elasticsearch import Elasticsearch
            from elasticsearch import helpers
            self.helpers = helpers
            self.es = Elasticsearch(ELASTIC_SEARCH_URL)

    def update_db(self):
        if environ.get('http_proxy') is not None:
            http = ProxyManager(environ.get('http_proxy'),maxsize=10)
        else:
            http = PoolManager()
        disable_warnings(urllib3_exceptions.InsecureRequestWarning)

        r= None
        meta = None

        try:
            r = http.request('GET', FEED_URL + 'official-cpe-dictionary_v2.3.meta', preload_content=False)
        except Exception as e:
            print("[!] Error obtaining CPE dictionary meta data: " + str(e))

        if path.isfile(self.meta_file_path):
            with open(self.meta_file_path, 'r') as myfile:
                meta = myfile.read()
            if r is not None and r.data.decode('utf-8').replace('\r','') == meta:
                return
        else:
            if r is not None:
                with open(self.meta_file_path, 'wb') as out_file:
                    copyfileobj(r,out_file)
        try:
            with http.request('GET', FEED_URL+'official-cpe-dictionary_v2.3.xml.zip', preload_content=False) as r, open(self.zipfile_location, 'wb') as out_file:
                copyfileobj(r, out_file)
        except Exception as e:
            print("[!] Error downloading CPE dictionary: " + str(e))
            return

        try:
            archive = ZipFile(self.zipfile_location, 'r')
            xml_data = archive.extract('official-cpe-dictionary_v2.3.xml',CACHE_PATH)
        except Exception as e:
            print("[!] Error extracting the CPE archive: " + str(e))
            return

        try:
            root = ET.parse(self.cpe_dictionary_filename).getroot()
        except ET.ParseError as e:
            print("[!] Error while parsing CPE dictionary: " + str(e))
            return

        cpe_dictionary = []
        cpe_names = {}
        actions = []
        count = 0
        for i in root.getchildren()[1:]:
            item = cpe_item()
            item.name = i.attrib['name']
            try:
                if i.attrib['deprecated'] is 'true':
                    item.deprecated = True
            except:
                item.deprecated = False

            for j in i.getchildren():
                if 'title' in j.tag:
                    item.title = j.text
                elif 'references' in j.tag:
                    for k in j.getchildren():
                        item.ref[k.attrib['href']] = k.text
                elif 'cpe23-item' in j.tag:
                    item.wfs = j.attrib['name']
            cpe_names[item.name] = item.title
            if USE_ELASTIC_SEARCH:
                actions.append({
                    "_index": "cpe-names",
                    "_type": "names",
                    "_source": {
                        'cpe_id': item.name,
                        'title': item.title,
                        'vendor': item.get_vendor(),
                        'product': item.get_product(),
                        'version': item.get_version(),
                        'wfs': item.wfs,
                        'cache-index': count,
                    }
                })
                count = count + 1
            cpe_dictionary.append(item)


        if USE_ELASTIC_SEARCH:
            try:
                if self.es.indices.exists(index="cpe-names"):
                    self.es.indices.delete(index='cpe-names', ignore=[400, 404])
                mappings = {
                    "mappings" : {
                        "names" : {
                            "properties" : {
                                "cpe_id" : {
                                    "type" : "keyword"
                                },
                                "wfs" : {
                                    "type": "keyword"
                                },
                                "product" : {
                                    "type": "keyword"
                                },
                                "version" : {
                                    "type": "keyword"
                                },
                                "vendor" : {
                                    "type": "keyword"
                                }
                            }
                        }
                    }
                }
                self.es.indices.create(index="cpe-names", ignore=400, body=mappings)
                self.helpers.bulk(self.es, actions,request_timeout=30)
            except Exception as e:
                print("[!] Elasticsearch indexing error: " + str(e))

        try:
            dump(cpe_dictionary, open(self.cpe_cache_filename, "wb"), HIGHEST_PROTOCOL)
            dump(cpe_names, open(self.cpe_names_filename, "wb"), HIGHEST_PROTOCOL)
            remove(self.cpe_dictionary_filename)
            remove(self.zipfile_location)
        except PickleError as e:
            print("[!] Error while caching CPE data: " + str(e))

    def get_all_cpe(self):
        try:
            list_items = load(open(self.cpe_names_filename, "rb"))
        except PickleError as e:
            print("Error while loading CPE database. Error: %s." % e.message)
            return [-2,'db']
        return list_items


    def add_cpe(self, uri, server_id):
        obj = None
        if component.objects.filter(cpe_id=uri).exists():
            obj = component.objects.get(cpe_id=uri)
        elif component.objects.filter(wfs=uri).exists():
            obj = component.objects.get(wfs=uri)
        else:
            if USE_ELASTIC_SEARCH:
                query1 = {"query" : {"constant_score" : {"filter" : {"term" : {"cpe_id" : uri}}}}}
                query2 = {"query" : {"constant_score" : {"filter" : {"term" : {"wfs" : uri}}}}}
                res1 = self.es.search(index="cpe-names",body=query1)
                if res1["hits"]["total"] == 1:
                    obj = component(cpe_id=res1["hits"]["hits"][0]["_source"]["cpe_id"],title=res1["hits"]["hits"][0]["_source"]["title"],wfs=res1["hits"]["hits"][0]["_source"]["wfs"])
                else:
                    res2 = self.es.search(index="cpe-names",body=query2)
                    if res2["hits"]["total"] == 1:
                        obj = component(cpe_id=res2["hits"]["hits"][0]["_source"]["cpe_id"],title=res2["hits"]["hits"][0]["_source"]["title"],wfs=res2["hits"]["hits"][0]["_source"]["wfs"])
            else:
                try:
                    list_items = load(open(self.cpe_cache_filename, "rb"))
                except PickleError as e:
                    print("Error while loading CPE database. Error: %s." % e.message)
                    return [-2]
                for item in list_items:
                    if item.name == uri:
                        obj = component(cpe_id=item.name,title=item.title,wfs=item.wfs)
                    elif item.wfs == uri:
                        obj = component(cpe_id=item.name,title=item.title,wfs=item.wfs)
        if obj is None:
            return [0]
        obj.save()
        ser = server.objects.get(id=server_id)
        if component_to_server.objects.filter(cpe=obj, server=ser).exists():
            return [-1, obj.title]
        new_comp = component_to_server(cpe=obj, server=ser)
        new_comp.save()
        return [1,obj.title,]


class Rpm:

    cpe_name=''
    cpe_names_filename = path.join(CACHE_PATH,'cpe_names.db')

    def __init__(self):

        if USE_ELASTIC_SEARCH:
            from elasticsearch import Elasticsearch
            self.es = Elasticsearch(ELASTIC_SEARCH_URL)

    def set_rpm(self, rpm_name):
        try:
            self.rpm_name = rpm_name.split(" ")[0]
            self.version = rpm_name.split(" ")[1]
            try:
                self.arch = rpm_name.split(" ")[2]
            except:
                self.arch = ''
        except:
            return -1


    def get_cpe(self):
        cpe = ['cpe:/a']
        cpe.append('*')
        cpe.append(self.rpm_name)
        cpe.append('*')
        self.cpe_name = ':'.join(cpe)

        partial_match = []
        exact_match = []

        if USE_ELASTIC_SEARCH:
            query = {"query": {"term": {"product": self.rpm_name}}}
            res = self.es.search(index="cpe-names",body=query,size=1000)
            list_items = []
            for item in res["hits"]["hits"]:
                list_items.append(item["_source"]["cpe_id"])
        else:
            try:
                list_items = load(open(self.cpe_names_filename, "rb"))
            except PickleError as e:
                print("Error while loading CPE database. Error: %s." % e.message)

        for item in list_items:

            if item.split(':')[3] != self.rpm_name:
                continue
            if parse_version(self.version) < parse_version(item.split(":")[4]):
                continue
            elif parse_version(self.version) == parse_version(item.split(":")[4]):
                exact_match.append(item)
                partial_match.append(item)
                continue
            flag = 0
            for x,y in zip(item.split(":")[4].split('.'),self.version.split('.')):
                if x != y:
                    flag = 1
                    break
            if flag is 1:
                continue
            partial_match.append(item)


        if exact_match is []:
            return partial_match
        else:
            return exact_match
