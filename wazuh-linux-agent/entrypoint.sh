#!/bin/bash
echo "002 Ruth-Linux 127.0.0.1 9b951a3128 6dc820452 2f36c9a18f144919a090545ef130114345258f085c200" > /var/ossec/etc/client.keys
chmod 640 /var/ossec/etc/client.keys
/var/ossec/bin/wazuh-control start
tail -f /var/ossec/logs/ossec.log
