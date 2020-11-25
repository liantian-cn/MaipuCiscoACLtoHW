#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __author__ = 'Lian Tian'
# __email__ = "liantian.me+code@gmail.com"
#
# MIT License

import re
import xlsxwriter
from datetime import datetime
from gooey import Gooey, GooeyParser

SRV_TO_PORT = {'MCom': 443, 'afpovertcp': 548, 'auth': 113, 'bgp': 179, 'biff': 512, 'bootpc': 68, 'bootps': 67, 'chargen': 19, 'chat': 531, 'cmd': 514, 'comsat': 512, 'conference': 531,
               'courier': 530, 'crs': 507, 'daytime': 13, 'dhcpc': 68, 'dhcps': 67, 'dhcpv6-client': 546, 'dhcpv6-server': 547, 'discard': 9, 'domain': 53, 'doom': 666, 'echo': 7, 'efs': 520,
               'epmap': 135, 'exec': 512, 'finger': 79, 'ftp': 21, 'ftp-data': 20, 'ftps': 990, 'ftps-data': 989, 'gopher': 70, 'hmmp-ind': 612, 'hmmp-op': 613, 'hostname': 101, 'hostnames': 101,
               'hosts2-ns': 81, 'http': 80, 'http-rpc-epmap': 593, 'https': 443, 'ident tap': 113, 'ike': 500, 'imap': 143, 'imap4': 143, 'imaps': 993, 'ipx': 213, 'irc': 194, 'irc-serv': 529,
               'ircs': 994, 'isakmp': 500, 'iso-tsap': 102, 'kerberos': 88, 'kerberos-adm': 749, 'kerberos-iv': 750, 'kerberos-sec': 88, 'klogin': 543, 'kpasswd': 464, 'kpop': 1109, 'krb5': 88,
               'krcmd': 544, 'kshell': 544, 'ldap': 389, 'ldaps': 636, 'loc-srv': 135, 'login': 513, 'mail': 25, 'mdbs_daemon': 800, 'mftp': 349, 'microsoft-ds': 445, 'monitor': 561, 'ms-rome': 569,
               'ms-shuttle': 568, 'msexch-routing': 691, 'name': 42, 'nameserver': 42, 'nbdatagram': 138, 'nbname': 137, 'nbsession': 139, 'netbios-dgm': 138, 'netbios-ns': 137, 'netbios-ssn': 139,
               'netnews': 532, 'netwall': 533, 'new-rwho': 550, 'new-who': 550, 'newdate': 526, 'nfa': 1155, 'nfsd-keepalive': 1110, 'nfsd-status': 1110, 'nicname': 43, 'nntp': 119, 'nntps': 563,
               'ntalk': 518, 'ntp': 123, 'pcmail-srv': 158, 'pop2': 109, 'pop3': 110, 'pop3s': 995, 'portmap': 111, 'postoffice': 109, 'print-srv': 170, 'printer': 515, 'qotd': 17, 'quote': 17,
               'readnews': 532, 'remotefs': 556, 'resource': 39, 'rfs': 556, 'rfs_server': 556, 'rlp': 39, 'rmonitor': 560, 'rmonitord': 560, 'route': 520, 'routed': 520, 'router': 520, 'rpc': 530,
               'rpcbind': 111, 'rtelnet': 107, 'rtsp': 554, 'rtsps': 322, 'shell': 514, 'sink': 9, 'sldap': 636, 'smtp': 25, 'snmp': 161, 'snmp-trap': 162, 'snmptrap': 162, 'snntp': 563, 'source': 19,
               'spooler': 515, 'spop3': 995, 'sql-net': 150, 'sqlserv': 118, 'sqlsrv': 156, 'ssh': 22, 'sunrpc': 111, 'syslog': 514, 'systat': 11, 'talk': 517, 'telnet': 23, 'telnets': 992,
               'tempo': 526, 'tftp': 69, 'time': 37, 'timed': 525, 'timeserver': 525, 'timserver': 37, 'ttytst': 19, 'ulp': 522, 'usenet': 119, 'users': 11, 'uucp': 540, 'uucp-path': 117,
               'uucpd': 540, 'who': 513, 'whoami': 565, 'whod': 513, 'whois': 43, 'www': 80, 'www-http': 80}

__doc__ = """
这是一个将迈普的ACL转化为华为ACL的工具
"""

# print(content)

pattern_acl_ext = re.compile(r"^(ip access-list extended (?P<acl_name>.*)\n)"
                             r"(?P<acl_content>(((?!exit).)*\n)*)",
                             re.MULTILINE)

pattern_acl_std = re.compile(r"^(ip access-list standard (?P<acl_name>.*)\n)"
                             r"(?P<acl_content>(((?!exit).)*\n)*)",
                             re.MULTILINE)

pattern_entry = re.compile(r"^[\s\d]*(?P<rule_action>deny|permit)(?P<rule_content>.*)$")


class ACLObject(object):
    acl_type = None

    def __init__(self, acl_name, acl_content):
        self.acl_name = acl_name
        self.acl_content = acl_content
        self.entries = []
        self.parse_entry()

    def parse_entry(self):
        for line in self.acl_content.splitlines():
            line = line.strip()
            if len(line) > 5:
                self.entries.append(ACLEntry(line, self.acl_type))


class ACLEntry(object):
    def __init__(self, acl_entry_content, acl_type):
        self.content = acl_entry_content
        self.acl_type = acl_type
        self.rule_content = None
        self.rule_content_list = None
        self.rule_action = None
        self.protocol = None
        self.source_type = None
        self.source_addr = None
        self.source_wildcard = None
        self.source_port_operator = None
        self.source_port = None
        self.destination_type = None
        self.destination_addr = None
        self.destination_wildcard = None
        self.destination_port_operator = None
        self.destination_port = None
        self.result = None
        self.parse()
        self.hw_parse()

    def parse(self):
        q = pattern_entry.search(self.content)
        if q:
            self.rule_content = q.group("rule_content").strip()
            self.rule_action = q.group("rule_action").strip()
            self.rule_content_list = self.rule_content.split()

            # 扩展ACL读取协议
            if self.acl_type == "Extended":
                self.protocol = self.rule_content_list[0].lower().strip()
                self.rule_content_list = self.rule_content_list[1:]

            # 源地址读取
            if self.rule_content_list[0].lower().strip() == "any":
                self.source_type = "any"
                self.rule_content_list = self.rule_content_list[1:]
            elif self.rule_content_list[0].lower().strip() == "host":
                self.source_type = "host"
                self.source_addr = self.rule_content_list[1]
                self.rule_content_list = self.rule_content_list[2:]
            else:
                self.source_type = "net"
                self.source_addr = self.rule_content_list[0]
                self.source_wildcard = self.rule_content_list[1]
                self.rule_content_list = self.rule_content_list[2:]

            if self.acl_type == "Extended":
                # 源端口读取
                if self.rule_content_list[0].lower().strip() in ["wildcard", "range", "neq", "lt", "gt", "eq"]:
                    self.source_port_operator = self.rule_content_list[0].lower().strip()
                    self.source_port = self.rule_content_list[1]
                    self.rule_content_list = self.rule_content_list[2:]

                # 判断目的地址
                if self.rule_content_list[0].lower().strip() == "any":
                    self.destination_type = "any"
                    self.rule_content_list = self.rule_content_list[1:]
                elif self.rule_content_list[0].lower().strip() == "host":
                    self.destination_type = "host"
                    self.destination_addr = self.rule_content_list[1]
                    self.rule_content_list = self.rule_content_list[2:]
                else:
                    self.destination_type = "net"
                    self.destination_addr = self.rule_content_list[0]
                    self.destination_wildcard = self.rule_content_list[1]
                    self.rule_content_list = self.rule_content_list[2:]

                # 判断目的地址
                if len(self.rule_content_list) > 0 and self.rule_content_list[0].lower().strip() in ["wildcard", "range", "neq", "lt", "gt", "eq"]:
                    self.destination_port_operator = self.rule_content_list[0].lower().strip()
                    self.destination_port = self.rule_content_list[1]
                    self.rule_content_list = self.rule_content_list[2:]

                if self.source_port is not None:
                    self.source_port = SRV_TO_PORT.get(self.source_port, self.source_port)
                    try:
                        self.source_port = int(self.source_port)
                    except ValueError:
                        self.source_port = self.source_port
                if self.destination_port is not None:
                    self.destination_port = SRV_TO_PORT.get(self.destination_port, self.destination_port)
                    try:
                        self.destination_port = int(self.destination_port)
                    except ValueError:
                        self.destination_port = self.destination_port

            if len(self.rule_content_list) > 0:
                print(" ".join(self.rule_content_list))

        else:
            pass

    def hw_parse(self):
        if self.acl_type == "Standard":
            self.result = "{rule_action}".format(rule_action=self.rule_action)
        if self.acl_type == "Extended":
            self.result = "{rule_action} {protocol}".format(rule_action=self.rule_action, protocol=self.protocol)

        if self.source_type == "host":
            self.result += " source {source_addr} 0".format(source_addr=self.source_addr)
        if self.source_type == "net":
            self.result += " source {source_addr} {source_wildcard}".format(source_addr=self.source_addr, source_wildcard=self.source_wildcard)

        if self.source_port_operator is not None:
            self.result += " source-port {source_port_operator} {source_port}".format(source_port_operator=self.source_port_operator, source_port=self.source_port)

        if self.destination_type == "host":
            self.result += " destination {destination_addr} 0".format(destination_addr=self.destination_addr)
        if self.destination_type == "net":
            self.result += " destination {destination_addr} {destination_wildcard}".format(destination_addr=self.destination_addr, destination_wildcard=self.destination_wildcard)

        if self.destination_port_operator is not None:
            self.result += " destination-port {destination_port_operator} {destination_port}".format(destination_port_operator=self.destination_port_operator, destination_port=self.destination_port)

    def __repr__(self):
        return "ACLEntry({})".format(self.content)


class StandardACL(ACLObject):
    acl_type = "Standard"

    def __repr__(self):
        return "StandardACL({})".format(self.acl_name)


class ExtendedACL(ACLObject):
    acl_type = "Extended"

    def __repr__(self):
        return "ExtendedACL({})".format(self.acl_name)


def conv_file(filename):
    file_content = open(filename, "r", encoding="utf-8-sig").read()
    ALL_ACL = []

    for acl in pattern_acl_std.finditer(file_content):
        ALL_ACL.append(StandardACL(acl_name=acl.group("acl_name"), acl_content=acl.group("acl_content")))

    for acl in pattern_acl_ext.finditer(file_content):
        ALL_ACL.append(ExtendedACL(acl_name=acl.group("acl_name"), acl_content=acl.group("acl_content")))

    workbook = xlsxwriter.Workbook(
        '{org_filename}_HW_{ext_name}.xlsx'.format(org_filename=filename.__str__(), ext_name=datetime.now().strftime("%Y-%m-%d %H-%M")),
        {'constant_memory': True})

    # 源格式
    ori_format = workbook.add_format()
    # ori_format.set_bold()
    ori_format.set_bg_color("#FC0356")
    # 目标格式
    tar_format = workbook.add_format()
    # tar_format.set_bold()
    tar_format.set_bg_color("#03B1FC")
    # 标题
    tit_format = workbook.add_format()
    tit_format.set_bold()

    sheet = workbook.add_worksheet()
    row = 0
    sheet.write(row, 0, '原本条目')
    sheet.write(row, 1, '目的条目')
    acl_count = 0

    for ACL in ALL_ACL:
        row += 2
        acl_count += 1
        entry_count = 1
        if ACL.acl_type == "Standard":
            sheet.write(row, 0, "ip access-list standard {name}".format(name=ACL.acl_name), tit_format)
            sheet.write(row, 1, "acl name {name} {acl_no}".format(name=ACL.acl_name, acl_no=500 * acl_count), tit_format)
        if ACL.acl_type == "Extended":
            sheet.write(row, 0, "ip access-list extended {name}".format(name=ACL.acl_name), tit_format)
            sheet.write(row, 1, "acl name {name} {acl_no}".format(name=ACL.acl_name, acl_no=500 * acl_count), tit_format)
        row += 1
        for entry in ACL.entries:
            sheet.write(row, 0, entry.content, ori_format)
            sheet.write(row, 1, " rule {count} {result}".format(count=entry_count * 10, result=entry.result), tar_format)
            row += 1
            entry_count += 1
    workbook.close()






@Gooey(language='chinese',program_name='MaipuACL')
def main():
    parser = GooeyParser(description='处理ACL的小工具')

    parser.add_argument('filename', help="需要读取的文件", widget='FileChooser') 
    args = parser.parse_args()
    conv_file(args.filename)


if __name__ == '__main__':
    main()