# PPPOE_L2TP_linkmonitoring

Python script to retrieve via SNMP the users connected via L2TP and PPPOE on Redback and Cisco devices.
Then classifies users by type based on connection realm or vlan.
Then push the values into an influxdb table, in order to create a monitoring dashboard.
