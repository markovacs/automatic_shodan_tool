# imports

from datetime import datetime
from netaddr import *
import shodan
import pandas as pd
import csv
from config import API_KEY, IP_ranges

# define api

api = shodan.Shodan ( API_KEY )

# define variables

today = datetime.today ().strftime ( '%Y_%m_%d' )


def shodan_to_csv(IP_range):
    filename = today + '_' + IP_range.replace ( '.', '_' ).replace ( '/', '_' ) + '.csv'
    open ( filename, 'w' ).close ()
    header_exists = False

    ipnumber = 0

    for ip in IPSet ( [IP_range] ):
        try:
            result = api.host ( str ( ip ) )
            ipnumber += 1
        except:
            continue
        ip = (result['ip_str'])
        hostnames = (result['hostnames'])

        print ( ip )
        # print(hostnames)

        info = []
        cipher_version = []
        cipher_key = []
        status = []
        ssl_versions = []

        cipher_name_data = False
        cipher_key_data = False
        ssl_versions_data = False

        for i in range ( len ( result['data'] ) ):
            try:
                status.append ( result['data'][i]['http']['status'] )
            except:
                pass
            try:
                info.append ( result['data'][i]['http']['server'] )
            except:
                pass
            try:
                if not cipher_name_data:
                    if 'DES' in result['data'][i]['ssl']['cipher']['name']:
                        cipher_name_data = True
                    elif 'RC4' in result['data'][i]['ssl']['cipher']['name']:
                        cipher_name_data = True
                    else:
                        cipher_name_data = False
                if not cipher_key_data:
                    if (result['data'][i]['ssl']['cipher']['bits'] < 224) or (
                            1000 < result['data'][i]['ssl']['cipher']['bits'] < 2048):
                        cipher_key_data = True
                    else:
                        cipher_key_data = False
                for version in result['data'][i]['ssl']['versions']:
                    if not ssl_versions_data:
                        if 'TLSv1.1' in version:
                            ssl_versions_data = True
                            break
                        elif 'SSLv2' in version:
                            ssl_versions_data = True
                            break
                        elif 'SSLv3' in version:
                            ssl_versions_data = True
                            break
                        else:
                            ssl_versions_data = False
            except:
                continue
        cipher_version = int ( cipher_name_data )
        cipher_key = int ( cipher_key_data )
        ssl_versions = int ( ssl_versions_data )
        if 200 not in status: continue
        # print(info)
        # print(status)
        # print(ssl_versions)
        # print(cipher_version)
        # print(cipher_key)

        CacheControl = 'Cache-Control'
        XFrameOptions = 'X-Frame-Options'
        XContentTypeOptions = 'X-Content-Type-Options'
        ContentSecurityPolicy = 'Content-Security-Policy'
        XPermittedCrossDomainPolicies = 'X-Permitted-Cross-Domain-Policies'
        ReferrerPolicy = 'Referrer-Policy'
        CrossOriginEmbedderPolicy = 'Cross-Origin-Embedder-Policy'
        CrossOriginOpenerPolicy = 'Cross-Origin-Opener-Policy'
        CrossOriginResourcePolicy = 'Cross-Origin-Resource-Policy'

        # True means the secure header is missing

        CacheControl = 1 if CacheControl not in str ( result ) else 0
        XFrameOptions = 1 if XFrameOptions not in str ( result ) else 0
        XContentTypeOptions = 1 if XContentTypeOptions not in str ( result ) else 0
        ContentSecurityPolicy = 1 if ContentSecurityPolicy not in str ( result ) else 0
        XPermittedCrossDomainPolicies = 1 if XPermittedCrossDomainPolicies not in str ( result ) else 0
        ReferrerPolicy = 1 if ReferrerPolicy not in str ( result ) else 0
        CrossOriginEmbedderPolicy = 1 if CrossOriginEmbedderPolicy not in str ( result ) else 0
        CrossOriginOpenerPolicy = 1 if CrossOriginOpenerPolicy not in str ( result ) else 0
        CrossOriginResourcePolicy = 1 if CrossOriginResourcePolicy not in str ( result ) else 0

        # print(CacheControl)
        # print(XFrameOptions)
        # print(XContentTypeOptions)
        # print(ContentSecurityPolicy)
        # print(XPermittedCrossDomainPolicies)
        # print(ReferrerPolicy)
        # print(CrossOriginEmbedderPolicy)
        # print(CrossOriginOpenerPolicy)
        # print(CrossOriginResourcePolicy)

        # Checking for CVEs
        CVEs = []
        try:
            CVEs = (result['vulns'])
        # print(CVEs)
        except:
            pass

        # Headers to avoid

        XXSSProtection = 'X-XSS-Protection: 1'
        XXSSProtection = 1 if XXSSProtection in str ( result ) else 0
        # print(XXSSProtection)
        result_csv = {"IP address": ip,
                      "hostnames": hostnames,
                      "info": info,
                      "status": status,
                      "Cache-Control": CacheControl,
                      "X-Frame-Options": XFrameOptions,
                      "X-Content-Type-Options": XContentTypeOptions,
                      "Content-Security-Policy": ContentSecurityPolicy,
                      "X-Permitted-Cross-Domain-Policies": XPermittedCrossDomainPolicies,
                      "Referrer-Policy": ReferrerPolicy,
                      "Cross-Origin-Embedder-Policy": CrossOriginEmbedderPolicy,
                      "Cross-Origin-Opener-Policy": CrossOriginOpenerPolicy,
                      "Cross-Origin-Resource-Policy": CrossOriginResourcePolicy,
                      "ssl_versions": ssl_versions,
                      "cipher_version": cipher_version,
                      "cipher_key": cipher_key,
                      "X-XSS-Protection": XXSSProtection,
                      "CVEs": CVEs}

        df = pd.DataFrame.from_dict ( result_csv, orient = 'index' )
        df = df.transpose ()
        if (not header_exists):
            df.to_csv ( filename, mode = 'a', index = False, header = True )
        else:
            df.to_csv ( filename, mode = 'a', index = False, header = False )
        header_exists = True
    return {'IP range': IP_range.replace ( '.', '_' ).replace ( '/', '_' ), 'Number of IPs': ipnumber}

header = False

open ( 'everyip.csv', 'w' ).close ()

all_ip = 0
all_vulns = 0

for IP_range in IP_ranges:

    everyip = shodan_to_csv ( IP_range )
    all_ip += everyip['Number of IPs']

    filename = today + '_' + IP_range.replace ( '.', '_' ).replace ( '/', '_' ) + '.csv'
    file = open ( filename )
    reader = csv.reader ( file )
    lines = len ( list ( reader ) )
    if lines == 0:
        pass
    else:
        lines -= 1
    all_vulns += lines

    df = pd.DataFrame.from_dict ( everyip, orient = 'index' )
    df = df.transpose ()

    if (not header):
        df.to_csv ( 'everyip.csv', mode = 'a', index = False, header = True )
    else:
        df.to_csv ( 'everyip.csv', mode = 'a', index = False, header = False )
    header = True

kpi = (all_vulns / all_ip) * 100
historical_data = {"Date": today.replace ( "_", "." ), "KPI": kpi}
df = pd.DataFrame.from_dict ( historical_data, orient = 'index' )
df = df.transpose ()
df.to_csv ( 'historical_data.csv', mode = 'a', index = False, header = False )
