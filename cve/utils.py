from urllib3 import ProxyManager,PoolManager,disable_warnings,exceptions as urllib3_exceptions
from shutil import copyfileobj
from zipfile import ZipFile
from os import path,remove,environ
try:
    from cPickle import load, PickleError, dump, HIGHEST_PROTOCOL
except ImportError:
    from pickle import load, PickleError, dump, HIGHEST_PROTOCOL
import json
from .models import vulnerability,affects
from cpe.models import component,component_to_server
from products.models import server
from django.db.models import Q
from vms.settings import USE_ELASTIC_SEARCH
from pkg_resources import parse_version
from datetime import datetime

CVE_FEED_URL = 'http://nvd.nist.gov/feeds/json/cve/1.0/'
CVE_FEED_FILENAME = 'nvdcve-1.0-$$$$'
APP_ROOT = path.dirname(path.abspath(__file__))
CACHE_PATH = path.join(APP_ROOT,'cache')

def match_cpe(cpe_a,cpe_b,cpe_set):
    if 'cpe:2.3' in cpe_a:
        index = 5
    else:
        index = 4

    for x,y in zip(cpe_a.split(':')[:index] + cpe_a.split(':')[index+1:],cpe_b.split(':')[:index] + cpe_b.split(':')[index+1:]):
        if x in '*-~' or y in '*-~':
            continue
        elif x != y:
            return False

    try:
        v1 = cpe_a.split(':')[index]
    except:
        v1 = '*'

    if cpe_set["vStartE"] == cpe_set["vStartI"] == cpe_set["vEndE"] == cpe_set["vEndI"] == '':
        try:
            v2 = cpe_b.split(':')[index]
        except:
            v2 = '*'
        if v1 != '*' and v2 != '*':
            for x,y in zip(v1,v2):
                if x != y:
                    return False
    else:
        version = parse_version(v1)
        if ((cpe_set["vStartE"] is not '' and parse_version(cpe_set["vStartE"]) >= version) or
            (cpe_set["vStartE"] is not '' and parse_version(cpe_set["vStartI"]) > version) or
            (cpe_set["vEndE"] is not '' and parse_version(cpe_set["vEndE"]) <= version) or
            (cpe_set["vEndI"] is not '' and parse_version(cpe_set["vEndI"]) < version)):
            return False

    return True

class cve_item:
    def __init__(self):
        self.id = ''
        self.affected = []
        self.published = ''
        self.last_modified = ''
        self.cvss = {}
        self.references = []
        self.summary = ''


class cve_handler:

    def __init__(self):
        if USE_ELASTIC_SEARCH:
            from elasticsearch import Elasticsearch
            from elasticsearch import helpers
            self.helpers = helpers
            self.es = Elasticsearch()

    def update_db(self,year):
        filename = CVE_FEED_FILENAME.replace('$$$$',year) + '.json'
        file_path = path.join(CACHE_PATH,filename)
        meta_filename = CVE_FEED_FILENAME.replace('$$$$',year) + '.meta'
        meta_file_path = path.join(CACHE_PATH,year+'.meta')

        if environ.get('http_proxy') is not None:
            http = ProxyManager(environ.get('http_proxy'),maxsize=10)
        else:
            http = PoolManager()
        disable_warnings(urllib3_exceptions.InsecureRequestWarning)
        r = None
        meta = None
        try:
            r = http.request('GET', CVE_FEED_URL + meta_filename, preload_content=False)
        except Exception as e:
            print("[!] Error obtaining CVE meta data: " + str(e))

        if path.isfile(meta_file_path):
            with open(meta_file_path, 'r') as myfile:
                meta = myfile.read()
            if r is not None and meta is not None and r.data.decode('utf-8').replace('\r','') == meta:
                return

        else:
            if r is not None:
                with open(meta_file_path, 'wb') as out_file:
                    copyfileobj(r,out_file)

        try:
            with http.request('GET', CVE_FEED_URL + filename + '.zip', preload_content=False) as r, open(file_path + '.zip', 'wb') as out_file:
                copyfileobj(r, out_file)
        except Exception as e:
            print("[!] Error downloading CVE feed: " + str(e))
            return
        try:
            archive = ZipFile(file_path + '.zip', 'r')
            xml_data = archive.extract(filename, CACHE_PATH)
        except Exception as e:
            print("[!] Error extracting the CVE archive: " + str(e))
            return

        cve_cache = []
        actions = []
        count = 0

        with open(file_path, encoding='utf-8') as data_file:
            data = json.loads(data_file.read())["CVE_Items"]
        for i in data:
            item = cve_item()
            item.id = i["cve"]["CVE_data_meta"]["ID"]
            for j in i['cve']['references']['reference_data']:
                item.references.append(j)
            item.summary = i['cve']['description']['description_data'][0]["value"]
            for j in i['configurations']['nodes']:
                if 'cpe' in j:
                    for k in j['cpe']:
                        item.affected.append({
                            "vuln": k['vulnerable'],
                            "cpe22": k['cpe22Uri'],
                            "cpe23": k['cpe23Uri'],
                            "vStartE": k.get('versionStartExcluding',''),
                            "vStartI": k.get('versionStartIncluding',''),
                            "vEndE": k.get('versionEndExcluding',''),
                            "vEndI": k.get('versionEndIncluding','')
                        })
                elif 'children' in j:
                    for t in j['children']:
                        if 'cpe' in t:
                            for k in t['cpe']:
                                item.affected.append({
                                    "vuln": k['vulnerable'],
                                    "cpe22": k['cpe22Uri'],
                                    "cpe23": k['cpe23Uri'],
                                    "vStartE": k.get('versionStartExcluding',''),
                                    "vStartI": k.get('versionStartIncluding',''),
                                    "vEndE": k.get('versionEndExcluding',''),
                                    "vEndI": k.get('versionEndIncluding','')
                                })
            if 'baseMetricV3' in i['impact']:
                item.cvss['vector_string_v3'] = i['impact']['baseMetricV3']['cvssV3']['vectorString']
                item.cvss['score_v3'] = i['impact']['baseMetricV3']['cvssV3']['baseScore']
            if 'baseMetricV2' in i['impact']:
                item.cvss['vector_string_v2'] = i['impact']['baseMetricV2']['cvssV2']['vectorString']
                item.cvss['score_v2'] = i['impact']['baseMetricV2']['cvssV2']['baseScore']
            item.published = i['publishedDate']
            item.last_modified = i['lastModifiedDate']
            cve_cache.append(item)
            if USE_ELASTIC_SEARCH:
                actions.append({
                    "_index": "cve-"+year,
                    "_type": "vulns",
                    "_source": {
                        'cve_id': item.id,
                        'summary': item.summary,
                        'published': item.published,
                        'last_modified': item.last_modified,
                        'score_v3': item.cvss.get('score_v3',0),
                        'score_v2': item.cvss.get('score_v2',0),
                        'vector_string_v2': item.cvss.get('vector_string_v2','NA'),
                        'vector_string_v3': item.cvss.get('vector_string_v3','NA'),
                        'affected': item.affected,
                        'cache-index': count,
                    }
                })
                count = count + 1



        if USE_ELASTIC_SEARCH is True:
            try:
                self.es.indices.delete(index='cve-'+year, ignore=[400, 404])
                mappings = {
                    "mappings" : {
                        "vulns" : {
                            "properties" : {
                                "cve_id" : {
                                    "type" : "keyword"
                                },
                                "score_v2" : {
                                    "type" : "float"
                                },
                                "score_v3" : {
                                    "type" : "float"
                                },
                                "affected": {
                                    "type": "nested",
                                    "properties" : {
                                        "cpe22" : {
                                            "type" : "keyword"
                                        },
                                        "cpe23" : {
                                            "type" : "keyword"
                                        },
                                        "vStartE" : {
                                            "type" : "keyword"
                                        },
                                        "vStartI" : {
                                            "type" : "keyword"
                                        },
                                        "vEndE" : {
                                            "type" : "keyword"
                                        },
                                        "vEndI" : {
                                            "type" : "keyword"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                self.es.indices.create(index="cve-"+year, ignore=400, body=mappings)
                self.helpers.bulk(self.es, actions)
            except Exception as e:
                print("[!] Elasticsearch indexing error: " + str(e))

        try:
            dump(cve_cache, open(path.join(CACHE_PATH,year+'.db'), "wb"), HIGHEST_PROTOCOL)
            remove(file_path + '.zip')
            remove(file_path)
        except PickleError as e:
            print("[!] Error while caching CVE data: " + str(e))

    def add_cve(self, cpe_name,ser_id):
        ser = server.objects.get(id=ser_id)
        if affects.objects.filter(Q(c2s__cpe__cpe_id=cpe_name)|Q(c2s__cpe__wfs=cpe_name)).exists():
            for item in affects.objects.filter(Q(c2s__cpe__cpe_id=cpe_name)|Q(c2s__cpe__wfs=cpe_name)):
                if component.objects.filter(cpe_id=cpe_name).exists():
                    cpe_item = component.objects.get(cpe_id=cpe_name)
                else:
                    cpe_item = component.objects.get(wfs=cpe_name)
                c2s = component_to_server.objects.get(server=ser,cpe=cpe_item)
                rel = affects(cve=item.cve,c2s=c2s,custom_score=0,server=ser)
                rel.save()
        else:
            if USE_ELASTIC_SEARCH:
                if 'cpe:2.3' in cpe_name:
                    ind = 5
                else:
                    ind = 4

                cpe_wildcard = ":".join(cpe_name.split(":",ind)[:ind]) + '*'

                query = {
                    "query": {
                        "nested" : {
                            "path" : "affected",
                            "score_mode" : "avg",
                            "query" : {
                                "bool" : {
                                    "must" : [
                                        { "wildcard" : {"affected.cpe22": {"wildcard": cpe_wildcard,"boost": "2.0"}} }
                                    ]
                                }
                            }
                        }
                    }
                }
                res = self.es.search(index=["cve-"+str(year) for year in range(2002,datetime.now().year+1)],body=query,size=10000)
                for item in res["hits"]["hits"]:
                    for comp in item["_source"]["affected"]:
                        if ((match_cpe(cpe_name,comp['cpe22'],comp) or match_cpe(cpe_name,comp['cpe23'],comp)) and comp['vuln']) is True:
                            if vulnerability.objects.filter(cve_id=item["_source"]["cve_id"]).exists():
                                vuln = vulnerability.objects.get(cve_id=item["_source"]["cve_id"])
                            else:
                                vuln = vulnerability(
                                    cve_id = item["_source"]["cve_id"],
                                    summary = item["_source"]["summary"],
                                    published = item["_source"]["published"],
                                    last_modified = item["_source"]["last_modified"],
                                    score_v2 = item["_source"]["score_v2"],
                                    score_v3 = item["_source"]["score_v3"],
                                    vector_string_v2 = item["_source"]["vector_string_v2"],
                                    vector_string_v3 = item["_source"]["vector_string_v3"],
                                )
                                vuln.save()
                            if component.objects.filter(cpe_id=cpe_name).exists():
                                cpe_item = component.objects.get(cpe_id=cpe_name)
                            elif component.objects.filter(wfs=cpe_name).exists():
                                cpe_item = component.objects.get(wfs=cpe_name)
                            else:
                                return
                            if server.objects.filter(id=ser_id).exists():
                                c2s = component_to_server.objects.get(server=ser,cpe=cpe_item)
                                rel = affects(cve=vuln,c2s=c2s,custom_score=0,server=ser)
                                rel.save()
            else:
                for year in range(2002,datetime.now().year+1):
                    try:
                        list_items = load(open(path.join(CACHE_PATH,str(year)+'.db'), "rb"))
                    except PickleError as e:
                        print("Error while loading CVE database. Error: %s." % e.message)
                        continue
                    for item in list_items:
                        for comp in item.affected:
                            if ((match_cpe(cpe_name,comp['cpe22'],comp) or match_cpe(cpe_name,comp['cpe23'],comp)) and comp['vuln']) is True:
                                if vulnerability.objects.filter(cve_id=item.id).exists():
                                    vuln = vulnerability.objects.get(cve_id=item.id)
                                else:
                                    vuln = vulnerability(
                                        cve_id = item.id,
                                        summary = item.summary,
                                        published = item.published,
                                        last_modified = item.last_modified,
                                        score_v2 = item.cvss.get('score_v2',0),
                                        score_v3 = item.cvss.get('score_v3',0),
                                        vector_string_v2 = item.cvss.get('vector_string_v2','NA'),
                                        vector_string_v3 = item.cvss.get('vector_string_v3','NA'),
                                    )
                                    vuln.save()
                                if component.objects.filter(cpe_id=cpe_name).exists():
                                    cpe_item = component.objects.get(cpe_id=cpe_name)
                                elif component.objects.filter(wfs=cpe_name).exists():
                                    cpe_item = component.objects.get(wfs=cpe_name)
                                else:
                                    return
                                if server.objects.filter(id=ser_id).exists():
                                    c2s = component_to_server.objects.get(server=ser,cpe=cpe_item)
                                    rel = affects(cve=vuln,c2s=c2s,custom_score=0,server=ser)
                                    rel.save()
