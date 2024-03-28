import dns.edns
import dns.message
import dns.rdatatype
from dns import message as dns_message
from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP


def setup_logger(log_file):
    # 检查是否已经存在具有相同名称的 logger 对象
    if log_file in logging.Logger.manager.loggerDict:
        return logging.getLogger("runlog")

    # 创建一个logger
    logger = logging.getLogger("runlog")

    # 创建一个handler，用于写入日志文件
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)

    # 创建一个handler，用于输出到控制台
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    # 定义handler的输出格式
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # 给logger添加handler
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


class DNSHandler:
    flag_RD = False
    loger = setup_logger("DNSHandler.log")
    query_timeout = 2

    def create_dns_request(self, domain, record_type, client_ip=None):
        try:
            # 创建 DNS 请求消息
            request = dns_message.make_query(domain, dns.rdatatype.__dict__[record_type])
            if not self.flag_RD:
                request.flags &= ~dns.flags.RD

            # 添加 EDNS 选项（如果提供了客户端 IP）
            if client_ip:
                ecs_option = dns.edns.ECSOption(client_ip, srclen=32)
                request.use_edns(edns=True, options=[ecs_option], payload=4096)
            else:
                # 没有提供客户端 IP，则不携带 EDNS 选项，考虑了一下不携带也开启edns吧，防止返回过大导致截断。
                request.use_edns(edns=True, payload=4096)

            # 将 DNS 请求消息转换为字节数据
            dns_req_bytes = request.to_wire()

            return dns_req_bytes
        except (dns.message.UnknownRdatatype, dns.name.LabelTooLong) as e:
            self.loger.error("Error creating DNS request:", e)
            return None

    def send_dns_request(self, dst_ip, dns_req_bytes, src=None):
        try:
            # 构造 DNS 数据包
            src_port = RandShort()  # 构造随机端口，不然源端口全是53
            if src:
                dns_packet = IP(src=src, dst=dst_ip) / UDP(dport=53, sport=src_port) / DNS(dns_req_bytes)
                # 发送 DNS 数据包
                dns_response = sr1(dns_packet, verbose=0, timeout=self.query_timeout)
            else:
                dns_packet = IP(dst=dst_ip) / UDP(dport=53, sport=src_port) / DNS(dns_req_bytes)
                # 发送 DNS 数据包
                dns_response = sr1(dns_packet, verbose=0, timeout=self.query_timeout)

            return dns_response
        except Exception as e:
            self.loger.error("Error sending DNS request:", e)
            return None

    def extract_ips(self, answer_records):
        # print(answer_records)
        # 从 answer 记录中提取 IP 地址
        extracted_ips = []
        if '\n' in answer_records:
            for rdata_sp in answer_records.split('\n'):
                extracted_ips.append(' '.join(rdata_sp.split()[4:]))
        else:
            extracted_ips.append(' '.join(answer_records.split()[4:]))
        return ';'.join(sorted(extracted_ips))

    def dns_query(self, dnsserver, domain, record_type, client_ip=None, src=None):
        dns_req_bytes = self.create_dns_request(domain, record_type, client_ip)
        if dns_req_bytes is not None:
            dns_response = self.send_dns_request(dnsserver, dns_req_bytes, src=src)
            if dns_response is not None:
                dns_resp_bytes = bytes(dns_response[DNS])
                dns_resp_msg = dns_message.from_wire(dns_resp_bytes)
                rcode = dns_resp_msg.rcode()
                # 当 rcode 为 NXDOMAIN 时，不需要返回任何内容
                if rcode == 3:
                    return "NXDOMAIN", domain, record_type, ""
                elif rcode == 0:
                    # 如果 answer 记录不为空，获取 A 记录的 IP 地址
                    answer_records = dns_resp_msg.answer
                    authority_records = dns_resp_msg.authority
                    additional_records = dns_resp_msg.additional
                    if answer_records:
                        extracted_ips = []
                        for i in answer_records:
                            extracted_ips.append(self.extract_ips(i.to_text()))
                        return "NOERROR", domain, record_type, ';'.join(extracted_ips)
                    elif authority_records:
                        extracted_ips_au = []
                        for i in authority_records:
                            if "\n" in i.to_text():
                                extracted_ips_au.extend(i.to_text().split("\n"))
                            else:
                                extracted_ips_au.append(i.to_text())
                        if additional_records:
                            for additional in additional_records:
                                if "\n" in additional.to_text():
                                    extracted_ips_au.extend(additional.to_text().split("\n"))
                                else:
                                    extracted_ips_au.append(additional.to_text())
                        # print(';'.join(extracted_ips_au))
                        return "NoAnswer", domain, record_type, ';'.join(extracted_ips_au)
                    else:
                        return "NoAnswerNoAuthority", domain, record_type, ''
                else:
                    return rcode_to_string(rcode), domain, record_type, ""
            else:
                self.loger.error(f"{dnsserver} No response received. :{domain} src:{src}")
                return 'TIMEOUT', domain, record_type, ""
        else:
            return 'TIMEOUT', domain, record_type, ""


def rcode_to_string(rcode):
    rcode_dict = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
        # 添加其他可能的返回码...
    }

    return rcode_dict.get(rcode, "UNKNOWN")


# 示例用法
if __name__ == "__main__":
    dns_handler = DNSHandler()
    loger = setup_logger('run.log')
    loger.setLevel("DEBUG")
    loger.info(dns_handler.dns_query('192.168.123.1', 'www.baidu.com', 'A', '192.168.123.22'))
    loger.info(dns_handler.dns_query('192.168.123.1', 'www.baidu.com', 'A'))
    loger.info(dns_handler.dns_query('192.168.123.1', 'www.baidu.com', 'A', src='1.1.1.1'))
    loger.info(dns_handler.dns_query('192.168.123.1', 'www.baidu.com', 'A', client_ip='8.8.8.8', src='1.1.1.1'))
    loger.info(dns_handler.dns_query('114.114.114.114', 'www.chihuo.fun', 'A'))
