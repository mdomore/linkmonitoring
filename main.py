# Imports
import netsnmp
import json
import psycopg2
import time
import re
import sys
import os
import pandas as pd
from io import StringIO

# Variables and Constants

OID_CISCO_1 = '.1.3.6.1.4.1.9.9.786.1.2.1.1.6.1.1'
OID_CISCO_22 = '.1.3.6.1.4.1.9.9.786.1.1.1.1.22'
OID_CISCO_23 = '.1.3.6.1.4.1.9.9.786.1.1.1.1.23'
OID_CISCO_24 = '.1.3.6.1.4.1.9.9.786.1.1.1.1.24'

re_new_login = re.compile('^\w{2}\d{6,8}-\d-L\d{2}')

dict_connected = {'username': [], 'last_down': [], 'last_up': [], 'status': [], 'subtype': [], 'login_status': []}

# Connection parameters
param_dic = {
    "host": "172.22.0.11",
    "database": "login_status",
    "user": "postgres",
    "password": "MilKa;MeuH"
}


def redbackSNMPWalk(data, ip, version, community):
    """
    Call a snmp walk on the designated REDBACK device (ip), retrieve list of connected subscriber
    :param ip:
    :param version:
    :param community:
    :return Vars: List of OID where usernames are encoded
    """
    session = netsnmp.Session(DestHost=ip, Version=version, Community=community)
    session.UseLongNames = 1
    oid = ".1.3.6.1.4.1.2352.2.27.1.1.1.1.3"
    var = netsnmp.Varbind(oid)
    vars_list = netsnmp.VarList(var)
    print("--- %s seconds ---" % (time.time() - start_time))
    print(f'Snmp walk to {ip}')
    subscribers = (session.walk(vars_list))
    i = 0
    for sub in subscribers:
        vlan = redbackVlanFind(sub)
        user = redbackLoginDecode(vars_list[i].tag)
        realm = ".".join(user.split('@')[1].split('.')[1:3])
        if vlan != 0:
            vlan = vlan
        else:
            vlan = loginClassify(data, realm)
        dict_connected['username'].append(user)
        dict_connected['last_down'].append(0)
        dict_connected['last_up'].append(psycopg2.TimestampFromTicks(time.time() // 1))
        dict_connected['status'].append(True)
        dict_connected['subtype'].append(vlan)
        dict_connected['login_status'].append(True)
        i += 1


def redbackLoginDecode(sub):
    """
    Decode login username from SNMP gathered data
    :param sub:
    :return:
    """
    # split1 = sub.split('.1.3.6.1.4.1.2352.2.27.1.1.1.1.3.')
    split1 = sub.split('.iso.org.dod.internet.private.enterprises.2352.2.27.1.1.1.1.3.')
    split2 = split1[1].split('.', 1)
    j = int(split2[0])
    split3 = split2[1].split('.', j)[:j]
    login = ""
    for c in split3:
        login = login + chr(int(c))
    return login


def redbackVlanFind(sub):
    """

    :param sub:
    :return:
    """
    if b"L2TP LNS" in sub:
        vlan = 0
    else:
        vlan = sub.decode('utf-8').split()[4].split(':')[0]
    return vlan


def ciscoTotalSub(data, h, ip, version, community):
    """
    Get Total subs for each host

    OID : .1.3.6.1.4.1.9.9.786.1.2.1.1.6.1.1
    This object indicates the current number of subscriber session
    within the 'scope of aggregation' that have been authenticated.

    This function collect the total subscribers on each router.
    """
    var = netsnmp.Varbind(OID_CISCO_1)
    vars_list = netsnmp.VarList(var)
    session = netsnmp.Session(DestHost=ip, Version=version, Community=community)
    session.UseLongNames = 1
    sub_number = session.walk(vars_list)
    if sub_number:
        data['hosts'][h]['nb_sub'] = int(sub_number[0])
    else:
        data['hosts'][h]['nb_sub'] = 0


def ciscoSNMPGet(data, h, ip, version, community):
    """
    Get detailed subs

    OID : .1.3.6.1.4.1.9.9.786.1.1.1.1.22
    This object indicates the NAS port-identifier identifying the
    port on the NAS providing access to the subscriber.

    OID : .1.3.6.1.4.1.9.9.786.1.1.1.1.23
    This object indicates the domain associated with the
    subscriber.

    OID : .1.3.6.1.4.1.9.9.786.1.1.1.1.24
    This object indicates the username identifying the subscriber.

    This function collect information (NAS port, domain and username) about subscribers.
    """

    var_oid_22 = netsnmp.Varbind(OID_CISCO_22)
    var_oid_23 = netsnmp.Varbind(OID_CISCO_23)
    var_oid_24 = netsnmp.Varbind(OID_CISCO_24)
    vars_list = netsnmp.VarList(var_oid_22, var_oid_23, var_oid_24)
    session = netsnmp.Session(DestHost=ip, Version=version, Community=community)
    session.UseLongNames = 1
    print("--- %s seconds ---" % (time.time() - start_time))
    print(f'Snmp walk to {ip}')
    for i in range(data['hosts'][h]['nb_sub']):
        try:
            reply = session.getnext(vars_list)
            type = (int(reply[0].decode("utf-8").split('/')[-1].split('.')[0]))
            realm = (reply[1].decode("utf-8").split('.', 1)[1])
            user = (reply[2].decode("utf-8"))
            if type != 0:
                dict_connected['username'].append(user)
                dict_connected['last_down'].append(0)
                dict_connected['last_up'].append(psycopg2.TimestampFromTicks(time.time() // 1))
                dict_connected['status'].append(True)
                dict_connected['subtype'].append(type)
                dict_connected['login_status'].append(True)
            else:
                vlan = loginClassify(data, realm)
                dict_connected['username'].append(user)
                dict_connected['last_down'].append(0)
                dict_connected['last_up'].append(psycopg2.TimestampFromTicks(time.time() // 1))
                dict_connected['status'].append(True)
                dict_connected['subtype'].append(vlan)
                dict_connected['login_status'].append(True)
        except IndexError:
            print(reply)
            pass
        except ValueError:
            print(reply)
            pass
        except AttributeError:
            print(reply)
            pass


def loginClassify(data, realm):
    for t in data['type']:
        if data['type'][t]['realm'] == realm:
            try:
                vlan = data['type'][t]['vlan']
                return vlan
            except UnboundLocalError:
                print(realm)
                print(data['type'][t]['vlan'])
                pass


def connect(params_dic):
    """ Connect to the PostgreSQL database server """
    conn = 0
    try:
        # connect to the PostgreSQL server
        print('Connecting to the PostgreSQL database...')
        conn = psycopg2.connect(**params_dic)
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        sys.exit(1)
    print("Connection successful")
    return conn


def copy_from_file(conn, df, table):
    """
    Here we are going save the dataframe on disk as
    a csv file, load the csv file
    and use copy_from() to copy it to the table
    """
    # Save the dataframe to disk
    tmp_df = "./tmp_dataframe.csv"
    df.to_csv(tmp_df, index=False, header=False)
    f = open(tmp_df, 'r')
    cursor = conn.cursor()
    try:
        cursor.copy_from(f, table, sep=",")
        conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        os.remove(tmp_df)
        print("Error: %s" % error)
        conn.rollback()
        cursor.close()
        return 1
    print("copy_from_file() done")
    cursor.close()
    # os.remove(tmp_df)


def copy_from_stringio(conn, df, table):
    """
    Here we are going save the dataframe in memory
    and use copy_from() to copy it to the table
    """
    # save dataframe to an in memory buffer
    buffer = StringIO()
    df.to_csv(buffer, index=False, header=False)
    buffer.seek(0)

    cursor = conn.cursor()
    try:
        cursor.copy_from(buffer, table, sep=",")
        conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:

        print("Error: %s" % error)
        conn.rollback()
        cursor.close()
        return 1
    print("copy_from_stringio() done")
    cursor.close()


def main():
    with open("config.json") as json_data_file:
        data = json.load(json_data_file)
        for h in data['hosts']:
            ip = data['hosts'][h]['ip']
            brand = data['hosts'][h]['brand']
            '''
            Get logins connected to redback routers, store them in long_logins[] as dictionary{vlan: realm: user:}
            '''
            # if brand == 'redback':
            #     redbackSNMPWalk(data, ip, data['snmp']['version'], data['snmp']['community'])
            '''
            Get logins connected to cisco routers, store them in long_logins[] as dictionary{vlan: realm: user:}
            '''
            if brand == 'cisco':
                ciscoTotalSub(data, h, ip, data['snmp']['version'], data['snmp']['community'])
                ciscoSNMPGet(data, h, ip, data['snmp']['version'], data['snmp']['community'])

    df_connected = pd.DataFrame(data=dict_connected)

    conn = connect(param_dic)
    sql = """SELECT * FROM old_login;"""
    df_db = pd.read_sql_query(sql, conn)
    conn.close()

    frames = [df_connected, df_db]
    result = pd.concat(frames)

    print(df_db)
    print(df_connected)



    # result.to_csv(r'export_dataframe.csv', index=False, header=True)

    #print(result)

    # conn = connect(param_dic)  # connect to the database
    # # copy_from_stringio(conn, df, 'old_login')  # copy the dataframe to SQL
    # copy_from_file(conn, df, 'old_login')  # copy the dataframe to SQL
    # conn.close()  # close the connection


if __name__ == "__main__":
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))
