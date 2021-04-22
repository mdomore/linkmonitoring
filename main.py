# Imports
import netsnmp
import json
import psycopg2
import time
import re
import logging
from timeloop import Timeloop
from datetime import timedelta

# Variables and Constants
long_logins = []
link_logins = []
connected_logins = []
db_logins = []
result = []

short_logins = set()

OID_CISCO_1 = '.1.3.6.1.4.1.9.9.786.1.2.1.1.6.1.1'
OID_CISCO_22 = '.1.3.6.1.4.1.9.9.786.1.1.1.1.22'
OID_CISCO_23 = '.1.3.6.1.4.1.9.9.786.1.1.1.1.23'
OID_CISCO_24 = '.1.3.6.1.4.1.9.9.786.1.1.1.1.24'

tl = Timeloop()

re_new_login = re.compile('^\w{2}\d{6,8}-\d-L\d{2}')

select_all_query = """SELECT * FROM old_login;"""

update_round_timestamp = """
                        UPDATE all_purpose SET value = %s WHERE title = %s;
                        """

upsert_up = """
            INSERT INTO old_login (username, last_up, status, subtype, login_status) \
            VALUES (%s, %s, %s, %s, %s) \
            ON CONFLICT (username) \
            DO UPDATE SET last_up = %s, status = %s, subtype = %s, login_status = %s \
            WHERE old_login.username = %s;
            """

upsert_down = """
            INSERT INTO old_login (username, last_down, status, subtype, login_status) \
            VALUES (%s, %s, %s, %s, %s) \
            ON CONFLICT (username) \
            DO UPDATE SET last_down = %s, status = %s, subtype = %s, login_status = %s \
            WHERE old_login.username = %s;
            """


upsert_login_status_up = """
                        INSERT INTO old_login (username, login_status, last_up, subtype) \
                        VALUES (%s, %s, %s, %s) \
                        ON CONFLICT (username) \
                        DO UPDATE SET login_status = %s, last_up = %s, subtype = %s \
                        WHERE old_login.username = %s;
                        """

upsert_login_status_down = """
                        INSERT INTO old_login (username, login_status, last_down, subtype) \
                        VALUES (%s, %s, %s, %s) \
                        ON CONFLICT (username) \
                        DO UPDATE SET login_status = %s, last_down = %s, subtype = %s \
                        WHERE old_login.username = %s;
                        """

update_link_status = """
                     UPDATE old_login SET status = %s WHERE username = %s;
                     """


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
        connected_logins.append(
            {
                'user': user,
                'vlan': vlan,
                'status': True
            }
        )
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
            vlan = (int(reply[0].decode("utf-8").split('/')[-1].split('.')[0]))
            realm = (reply[1].decode("utf-8").split('.', 1)[1])
            user = (reply[2].decode("utf-8"))
            if vlan != 0:
                connected_logins.append(
                    {
                        'user': user,
                        'vlan': vlan,
                        'status': True
                    }
                )
            else:
                vlan = loginClassify(data, realm)
                connected_logins.append(
                    {
                        'user': user,
                        'vlan': vlan,
                        'status': True
                    }
                )
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


def push_login_to_db(cur, login, state, vlan):
    if state:
        cur.execute(upsert_login_status_up, (login, True, psycopg2.TimestampFromTicks(time.time() // 1), vlan,
                                             True, psycopg2.TimestampFromTicks(time.time() // 1), vlan, login))
    elif not state:
        cur.execute(upsert_login_status_down, (login, False, psycopg2.TimestampFromTicks(time.time() // 1), vlan,
                                               False, psycopg2.TimestampFromTicks(time.time() // 1), vlan, login))


def sql_conn():

    conn = psycopg2.connect(
        host="172.22.0.11",
        database="login_status",
        user="postgres",
        password="MilKa;MeuH")
    return conn


# Launch the script every X seconds
@tl.job(interval=timedelta(seconds=300))
def main():
    logging.info("starting link monitoring")
    '''
    Pushing collected data in DB
    '''
    conn = sql_conn()
    cur = conn.cursor()

    with open("config.json") as json_data_file:
        data = json.load(json_data_file)
        for h in data['hosts']:
            ip = data['hosts'][h]['ip']
            brand = data['hosts'][h]['brand']
            '''
            Get logins connected to redback routers, store them in long_logins[] as dictionary{vlan: realm: user:}
            '''
            if brand == 'redback':
                redbackSNMPWalk(data, ip, data['snmp']['version'], data['snmp']['community'])
            '''
            Get logins connected to cisco routers, store them in long_logins[] as dictionary{vlan: realm: user:}
            '''
            if brand == 'cisco':
                ciscoTotalSub(data, h, ip, data['snmp']['version'], data['snmp']['community'])
                ciscoSNMPGet(data, h, ip, data['snmp']['version'], data['snmp']['community'])
        '''
        push time of this round in db
        '''
        cur.execute(update_round_timestamp, (psycopg2.TimestampFromTicks(time.time() // 1), 'last_round'))
        '''
        Update link status for long_logins in new format <IP.........-.-L--@realm>
        '''
        print('SQL connected logins')
        print("--- %s seconds ---" % (time.time() - start_time))
        for c_login in connected_logins:
            link_logins.append(c_login['user'][:12])
            short_logins.add(c_login['user'])
            if 'factory' in c_login['user']:
                pass
            else:
                push_login_to_db(cur, c_login['user'], True, c_login['vlan'])

        print('SQL select all')
        print("--- %s seconds ---" % (time.time() - start_time))
        cur.execute(select_all_query)
        select_all = cur.fetchall()
        for db_login, db_date_down, db_date_up, db_link_status, db_type, db_login_status in select_all:
            db_logins.append(
                {
                    'user': db_login,
                    'vlan': db_type,
                    'status': db_login_status
                }
            )

        print('SQL db_login')
        print("--- %s seconds ---" % (time.time() - start_time))
        for db_login in db_logins:
            if 'factory' in db_login['user']:
                pass
            else:
                if db_login['user'] not in short_logins:
                    push_login_to_db(cur, db_login['user'], False, db_login['vlan'])
                if db_login['user'][:12] not in link_logins:
                    cur.execute(update_link_status, (False, db_login['user']))
                else:
                    cur.execute(update_link_status, (True, db_login['user']))
        '''
        SQL commit
        '''
        conn.commit()
        conn.close()
    print("PostgreSQL connection pool is closed")
    logging.info("stopping link monitoring")


if __name__ == "__main__":
    start_time = time.time()
    #tl.start(block=True)
    main()
    print("--- %s seconds ---" % (time.time() - start_time))
