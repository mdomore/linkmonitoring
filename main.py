# Imports
import netsnmp
import json
import psycopg2
import time
import re
import logging
from psycopg2 import extras
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

upsert = """
            INSERT INTO old_login (username, last_down, last_up, status, subtype, login_status) \
            VALUES %s \
            ON CONFLICT (username) \
            DO UPDATE SET last_up = excluded.last_up, status = excluded.status, subtype = excluded.subtype, \
            login_status = excluded.login_status WHERE old_login.username = excluded.username;
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
    logging.debug("--- %s seconds ---" % (time.time() - start_time))
    logging.debug(f'Snmp walk to {ip}')
    subscribers = (session.walk(vars_list))
    i = 0
    for sub in subscribers:
        subtype = redbackVlanFind(sub)
        user = redbackLoginDecode(vars_list[i].tag)
        realm = ".".join(user.split('@')[1].split('.')[1:3])
        if subtype != 0:
            subtype = subtype
        else:
            subtype = loginClassify(data, realm)
        connected_logins.append(
            (
                user,
                psycopg2.TimestampFromTicks(time.time() // 1),
                psycopg2.TimestampFromTicks(time.time() // 1),
                True,
                subtype,
                True
            )
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
    logging.debug("--- %s seconds ---" % (time.time() - start_time))
    logging.debug(f'Snmp walk to {ip}')
    for i in range(data['hosts'][h]['nb_sub']):
        try:
            reply = session.getnext(vars_list)
            subtype = (int(reply[0].decode("utf-8").split('/')[-1].split('.')[0]))
            realm = (reply[1].decode("utf-8").split('.', 1)[1])
            user = (reply[2].decode("utf-8"))
            if subtype != 0:
                connected_logins.append(
                    (
                        user,
                        psycopg2.TimestampFromTicks(time.time() // 1),
                        psycopg2.TimestampFromTicks(time.time() // 1),
                        True,
                        subtype,
                        True
                    )
                )
            else:
                subtype = loginClassify(data, realm)
                connected_logins.append(
                    (
                        user,
                        psycopg2.TimestampFromTicks(time.time() // 1),
                        psycopg2.TimestampFromTicks(time.time() // 1),
                        True,
                        subtype,
                        True
                    )
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
                subtype = data['type'][t]['vlan']
                return subtype
            except UnboundLocalError:
                print(realm)
                print(data['type'][t]['vlan'])
                pass


def sql_conn():
    conn = psycopg2.connect(
        host="10.10.10.1",
        database="database_name",
        user="user",
        password="password")
    return conn


# Launch the script every X seconds
# @tl.job(interval=timedelta(seconds=300))
def main():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s -  %(levelname)s - %(message)s')
    logging.debug('starting link monitoring')
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
        logging.debug('SQL connected logins')
        logging.debug("--- %s seconds ---" % (time.time() - start_time))
        for c_login in connected_logins:
            link_logins.append(c_login[0][:12])
            short_logins.add(c_login[0])
        c_logins = set(tuple(i) for i in connected_logins)
        psycopg2.extras.execute_values(cur, upsert, c_logins)
        conn.commit()

        logging.debug('SQL select all')
        logging.debug("--- %s seconds ---" % (time.time() - start_time))
        cur.execute(select_all_query)
        select_all = cur.fetchall()
        for db_login, db_last_down, db_last_up, db_link_status, db_type, db_login_status in select_all:
            db_logins.append(
                (
                    db_login,
                    db_last_down,
                    db_last_up,
                    db_link_status,
                    db_type,
                    db_login_status
                )
            )

        logging.debug('SQL db_login')
        logging.debug("--- %s seconds ---" % (time.time() - start_time))
        """
        For each login in db_login check if username(db_login[0]) is in short_login,
        if not set login status db_login[5] to False
        """
        [db_login[5] is False for db_login in db_logins if db_login[0] not in short_logins]
        """
        Same check for 12 first caracters of username for link status
        """
        [db_login[3] is False if db_login[0][:12] not in link_logins else db_login[3] is True for db_login in db_logins]
        c_logins = set(tuple(i) for i in db_logins)
        psycopg2.extras.execute_values(cur, upsert, c_logins)
        '''
        SQL commit
        '''
        conn.commit()
        conn.close()
    logging.debug("PostgreSQL connection pool is closed")
    logging.debug("stopping link monitoring")


if __name__ == "__main__":
    start_time = time.time()
    # tl.start(block=True)
    main()
    print("--- %s seconds ---" % (time.time() - start_time))
