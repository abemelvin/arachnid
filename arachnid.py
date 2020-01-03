from subprocess import Popen, PIPE, DEVNULL
import time
import os
import numpy as np
import pandas as pd
import multiprocessing as mp


def generate_logs(pcap_dir, pcap):
    volume = os.path.join(pcap_dir, ':/pcap:rw')
    container_name = 'zeek'
    print("Starting Zeek container to process {}".format(pcap))
    Popen(['docker', 'run', '--rm', '--name', container_name, '-v',
        volume, 'test/zeek', '-r', pcap, 'local'], stdout=PIPE)
    print("\n")
    print("{} processed.".format(pcap))
    print("\n")
    return

def test_json(data_dir, out_dir):
    volume = os.path.join(data_dir, 'conn.10:00:00-11:00:00.log')
    connections = pd.read_json(volume, lines=True)
    connections = connections[~(connections['conn_state'].str.contains('S0', na=False))]
    connections = connections[~(connections['conn_state'].str.contains('REJ', na=False))]
    connections = connections[~(connections['conn_state'].str.contains('RSTR', na=False))]
    connections = connections[~(connections['conn_state'].str.contains('RSTOS0', na=False))]
    first = connections.drop_duplicates(subset=['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto'], \
        keep='first')
    last = connections.drop_duplicates(subset=['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto'], \
        keep='last')
    connections = first.append(last)
    connections.drop_duplicates(subset=['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto', 'ts'], \
        keep='last', inplace=True)
    connections.to_json(out_dir + '/connections.csv', orient='records', lines=True)

def generate_nodes(data_dir, out_dir):

    def get_hosts(data_dir, out_dir):
        volume = os.path.join(data_dir, 'conn.10:00:00-11:00:00.log')
        connections = pd.read_json(volume, lines=True)
        orig = connections['id.orig_h'].unique()
        resp = connections['id.resp_h'].unique()
        hosts = np.unique(np.concatenate((orig, resp)))
        hosts = pd.DataFrame(hosts)
        hosts.dropna(axis=0, how='any', inplace=True)
        hosts.rename({0: 'name'}, axis='columns', inplace=True)
        hosts['type'] = 'EXTERNAL'
        hosts.loc[hosts['name'].str.startswith('192.168.', na=False), 'type'] = 'LOCAL NET'
        hosts.loc[hosts['name'].str.startswith('10.', na=False), 'type'] = 'J3 WEB OPS'
        hosts.loc[hosts['name'].str.startswith('64.129.', na=False), 'type'] = 'DIRTY NET'
        hosts.loc[hosts['name'].str.startswith('173.227.122.', na=False), 'type'] = 'CIPR DMZ'
        hosts.loc[hosts['name'].str.startswith('214.26.', na=False), 'type'] = 'NIPR'
        #hosts.index = range(len(hosts))
        #hosts.index += 1
        hosts.to_csv(out_dir + '/hosts.csv')#, index=True, header=False)

        #with open(data_dir + '/hosts.csv', 'r') as original:
        #    data = original.read()
        #with open(data_dir + '/hosts.csv', 'w') as modified:
        #    modified.write(":ID,name\n" + data)

    def get_domains(data_dir, out_dir):
        volume = os.path.join(data_dir, 'dns.10:00:00-11:00:00.log')
        queries = pd.read_json(volume, lines=True)
        queries = queries[~(queries['qtype_name'].str.contains('PTR', na=False))]
        queries = queries[~(queries['qtype_name'].str.contains('TXT', na=False))]
        queries = queries[~(queries['qtype_name'].str.contains('SRV', na=False))]
        queries = queries[~(queries['rcode_name'].str.contains('NXDOMAIN', na=False))]
        queries = queries[queries['query'] != '']
        domains = queries['query'].unique()
        domains = pd.DataFrame(domains)
        domains.dropna(axis=0, how='any', inplace=True)
        #domains.index = range(len(domains))
        #domains.index += 1

        #with open('whitelist.txt', 'r') as whitelist:
        #    for line in whitelist:
        #        host_whitelist.add(queries[queries['query'].str.endswith(line)].)
        #        domains = domains[~domains.iloc[:,-1].str.endswith(line)]

        domains.to_csv(out_dir + '/domains.csv')#, index=True, header=True)

        #with open(data_dir + '/domains.csv', 'r') as original:
        #    data = original.read()
        #with open(data_dir + '/domains.csv', 'w') as modified:
        #    modified.write(":ID,name\n" + data)

    p1 = mp.Process(target=get_hosts, args=(data_dir,out_dir))
    p2 = mp.Process(target=get_domains, args=(data_dir,out_dir))
    p1.start()
    p2.start()
    p1.join()
    p2.join()

def generate_relationships(data_dir, out_dir):

    def get_resolutions(data_dir, out_dir):
        hosts = pd.read_csv(out_dir + '/hosts.csv')
        volume = os.path.join(data_dir, 'dns.10:00:00-11:00:00.log')
        queries = pd.read_json(volume, lines=True)
        queries = queries.drop(['uid', 'id.orig_h', 'id.orig_p', \
            'id.resp_p', 'proto', 'trans_id', 'rcode', 'AA', 'TC', \
            'RD', 'RA', 'Z', 'TTLs', 'rejected'], axis=1)
        queries = queries[~(queries['qtype_name'].str.contains('PTR', na=False))]
        queries = queries[~(queries['qtype_name'].str.contains('TXT', na=False))]
        queries = queries[~(queries['qtype_name'].str.contains('SRV', na=False))]
        queries = queries[~(queries['rcode_name'].str.contains('NXDOMAIN', na=False))]
        queries.drop_duplicates(subset=['query', 'id.resp_h'], \
            keep='first', inplace=True)
        output = []

        for _, row in queries.iterrows():

            try:

                for answer in row.answers:
                    if answer not in set(hosts['name']):
                        continue
                    new_row = {}
                    new_row['ts'] = row.ts
                    new_row['query'] = row.query
                    new_row['answer'] = answer
                    new_row['resolver'] = row['id.resp_h']
                    output.append(new_row)
            except TypeError:
                pass

        queries = pd.DataFrame(output)
        queries.dropna(axis=0, how='any', inplace=True)
        queries.drop_duplicates(subset=['query', 'answer', 'resolver'], \
            keep='first', inplace=True)
        #queries.index = range(len(queries))
        #queries.index += 1
        queries.to_csv(out_dir + '/dns_resolutions.csv')#, index=True, header=False)

        #with open(data_dir + '/dns_resolutions.csv', 'r') as original:
        #    data = original.read()
        #with open(data_dir + '/dns_resolutions.csv', 'w') as modified:
        #    modified.write(":ID,ts,query,answer,server\n" + data)

    def get_connections(data_dir, out_dir, filter_unsuccessful=True):
        volume = os.path.join(data_dir, 'conn.10:00:00-11:00:00.log')
        connections = pd.read_json(volume, lines=True)
        connections = connections.drop(['uid', 'id.orig_p', 'service', 'duration', \
            'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', \
            'resp_ip_bytes', 'orig_bytes', 'resp_bytes'], axis=1)
        first = connections.drop_duplicates(subset=['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto'], \
            keep='first')
        last = connections.drop_duplicates(subset=['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto'], \
            keep='last')
        connections = first.append(last)
        connections.drop_duplicates(subset=['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto', 'ts'], \
            keep='last', inplace=True)

        if filter_unsuccessful:
            connections = connections[~(connections['conn_state'].str.contains('S0', na=False))]
            connections = connections[~(connections['conn_state'].str.contains('REJ', na=False))]
            connections = connections[~(connections['conn_state'].str.contains('RSTR', na=False))]
            connections = connections[~(connections['conn_state'].str.contains('RSTOS0', na=False))]

        #connections.index = range(len(connections))
        #connections.index += 1
        connections.to_csv(out_dir + '/connections.csv')#, index=True, header=False)

        #with open(data_dir + '/connections.csv', 'r') as original:
        #    data = original.read()
        #with open(data_dir + '/connections.csv', 'w') as modified:
        #    modified.write(":ID,ts,originator,responder,port,proto\n" + data)

    p1 = mp.Process(target=get_resolutions, args=(data_dir,out_dir))
    p2 = mp.Process(target=get_connections, args=(data_dir,out_dir,True))
    p1.start()
    p2.start()
    p1.join()
    p2.join()

def start_neo4j():
    base_dir = os.getcwd()
    print("Cleaning up old artifacts...")
    p = Popen(['docker', 'ps', '-aqf', 'name=hunt'], stdout=PIPE)
    containers = p.stdout.read().decode('UTF-8')[:-1]
    p = Popen(['docker', 'stop', containers], stdout=PIPE)
    out = p.stdout.read()
    p = Popen(['docker', 'rm', containers], stdout=PIPE)
    out = p.stdout.read()
    p = Popen(['sudo', 'rm', '-rf', base_dir + '/data/databases'], stdout=PIPE)
    out = p.stdout.read()
    p = Popen(['docker', 'build', '-t', 'arachnid/neo4j', '.'], stdout=PIPE)
    out = p.stdout.read()
    p = Popen(['docker', 'run', '-d', \
        '--name', 'hunt', \
        '--publish=7474:7474', '--publish=7687:7687', \
        '--volume=' + base_dir + '/data:/data', \
        '--volume=' + base_dir + '/logs:/logs', \
        '--volume=' + base_dir + '/plugins:/plugins', \
        '--volume=' + base_dir + '/zeek:/zeek', \
        #'--env=NEO4J_AUTH=neo4j/neo4j', \
        #'--env=NEO4J_ACCEPT_LICENSE_AGREEMENT=yes', \
        #'--env=NEO4J_apoc_import_file_enabled=true', \
        #'--env=NEO4J_dbms_security_procedures_unrestricted=apoc.*,algo.*', \
        '--env=NEO4J_dbms_activate__database=graph.db', \
        '--env=NEO4J_dbms_directories_data=/data', \
        #'--env=NEO4JLABS_PLUGINS=["apoc", "graph-algorithms"]', \
        'arachnid/neo4j'
        ], stdout=PIPE)
    out = p.stdout.read()

def import_hosts():
    p = Popen(['docker', 'exec', \
        'hunt', \
        '/bin/bash', '-c', \
        'cat /var/lib/neo4j/import/hosts.cypher | bin/cypher-shell' \
        ], stdout=PIPE)
    out = p.stdout.read()

def import_domains():
    p = Popen(['docker', 'exec', \
        'hunt', \
        '/bin/bash', '-c', \
        'cat /var/lib/neo4j/import/domains.cypher | bin/cypher-shell' \
        ], stdout=PIPE)
    out = p.stdout.read()

def import_dns_resolutions():
    p = Popen(['docker', 'exec', \
        'hunt', \
        '/bin/bash', '-c', \
        'cat /var/lib/neo4j/import/dns_resolutions.cypher | bin/cypher-shell' \
        ], stdout=PIPE)
    out = p.stdout.read()

def import_connections():
    p = Popen(['docker', 'exec', \
        'hunt', \
        '/bin/bash', '-c', \
        'cat /var/lib/neo4j/import/connections.cypher | bin/cypher-shell' \
        ], stdout=PIPE)
    out = p.stdout.read()

def delete_islands():
    p = Popen(['docker', 'exec', \
        'hunt', \
        '/bin/bash', '-c', \
        'echo "match (n) where not (n)--() delete (n)" | bin/cypher-shell' \
        ], stdout=PIPE)
    out = p.stdout.read()

def unzip_logs(data_dir):
    print("Decompressing connection logs...")
    p = Popen(['gunzip', '-f', data_dir + '/conn.*'], stdout=DEVNULL)
    print("Decompressing domain resolution logs...")
    p = Popen(['gunzip', '-f', data_dir + '/dns.*'], stdout=DEVNULL)

def implement_whitelist(data_dir, whitelist):
    hosts = pd.read_csv(data_dir + '/hosts.csv')
    hosts.drop(hosts.columns[0], axis=1, inplace=True)
    domains = pd.read_csv(data_dir + '/domains.csv')
    domains.drop(domains.columns[0], axis=1, inplace=True)
    connections = pd.read_csv(data_dir + '/connections.csv')
    connections.drop(connections.columns[0], axis=1, inplace=True)
    queries = pd.read_csv(data_dir + '/dns_resolutions.csv')
    queries.drop(queries.columns[0], axis=1, inplace=True)
    whitelist_hosts = set()

    with open(whitelist, 'r') as whitelist:
        for line in whitelist:
            line = line.rstrip("\n")
            if line is '': continue
            if len(domains[domains.iloc[:,-1].str.endswith(line)]) > 0:
                host = set(queries[queries['query'].str.endswith(line)]['answer'].unique())
                whitelist_hosts |= host
                queries = queries[~(queries['query'].str.endswith(line))]
                domains = domains[~(domains.iloc[:,-1].str.endswith(line))]
            if len(hosts[hosts['name'].str.startswith(line)]) > 0:
                host = set(hosts[hosts['name'].str.startswith(line)]['name'].unique())
                whitelist_hosts |= host
        whitelist_hosts = list(whitelist_hosts)
        hosts = hosts[~(hosts['name'].isin(whitelist_hosts))]
        connections = connections[~(connections['id.orig_h'].isin(whitelist_hosts))]
        connections = connections[~(connections['id.resp_h'].isin(whitelist_hosts))]

    hosts.index = range(len(hosts))
    hosts.index += 1
    hosts.to_csv(data_dir + '/hosts.csv', index=True, header=False)
    with open(data_dir + '/hosts.csv', 'r') as original:
        data = original.read()
    with open(data_dir + '/hosts.csv', 'w') as modified:
        modified.write(":ID,name,type\n" + data)

    domains.index = range(len(domains))
    domains.index += 1
    domains.to_csv(data_dir + '/domains.csv', index=True, header=False)
    with open(data_dir + '/domains.csv', 'r') as original:
        data = original.read()
    with open(data_dir + '/domains.csv', 'w') as modified:
        modified.write(":ID,name\n" + data)

    queries.index = range(len(queries))
    queries.index += 1
    queries.to_csv(data_dir + '/dns_resolutions.csv', index=True, header=False)
    with open(data_dir + '/dns_resolutions.csv', 'r') as original:
        data = original.read()
    with open(data_dir + '/dns_resolutions.csv', 'w') as modified:
        modified.write(":ID,ts,query,answer,resolver\n" + data)

    connections.index = range(len(connections))
    connections.index += 1
    connections.to_csv(data_dir + '/connections.csv', index=True, header=False)
    with open(data_dir + '/connections.csv', 'r') as original:
        data = original.read()
    with open(data_dir + '/connections.csv', 'w') as modified:
        modified.write(":ID,ts,originator,responder,port,proto,state\n" + data)


def main():
    data_dir = '/home/analytics/tempered_glass/logs/2019-10-24'
    out_dir = '/home/analytics/arachnid/zeek'
    whitelist = 'whitelist.txt'
    #test_json(data_dir, out_dir)
    print("Generating nodes...")
    generate_nodes(data_dir, out_dir)
    print("Mining for relationships...")
    generate_relationships(data_dir, out_dir)
    print("Whitelisting data...")
    implement_whitelist(out_dir, whitelist)
    start_neo4j()
    print("Giving Neo4j time to start...")
    time.sleep(30)
    print("Importing host nodes...")
    import_hosts()
    print("Importing domain nodes...")
    import_domains()
    print("Drawing relationships...")
    import_dns_resolutions()
    import_connections()
    #print("Removing island nodes...")
    #delete_islands()
    print("Done! Connect to graph in Neo4j desktop.")

if __name__ == '__main__':
    main()