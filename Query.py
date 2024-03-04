import argparse
import csv
import io
import ipaddress
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

from tqdm import tqdm

from Resolve import DNSHandler, setup_logger


def parse_arguments():
    """
    解析命令行参数
    """
    parser = argparse.ArgumentParser(
        description='ShadowResolve 数据包发送工具\n支持伪造源IP，也支持使用 ecs_client 地址的方式')

    # 添加命令行参数
    parser.add_argument('-s', '--spoof-source', action='store_true',
                        help='是否伪造源地址。默认为否。如果提供文件路径作为参数，则视为启用。')
    parser.add_argument('-e', '--ecs-enable', action='store_true',
                        help='是否使用 ECS 携带源地址。默认为否。如果提供文件路径作为参数，则视为启用。')
    parser.add_argument('-d', '--dnsserver', type=validate_ip_address, required=True,
                        help='指定 DNS 服务器地址。必须。')
    parser.add_argument('-t', '--thread', type=int, default=10,
                        help='指定线程数量，数量多，就快。但是不要超过10倍的cpu核心数，否则可能起到反效果')

    # -a 参数当 -s 或 -e 参数出现时必须提供
    parser.add_argument('-a', '--address-list', type=argparse.FileType('r'),
                        help='指定源地址的地址列表文件路径。',
                        required='-s' in sys.argv or '--spoof-source' in sys.argv or '-e' in sys.argv or '--ecs-enable' in sys.argv)
    parser.add_argument('--debug', action='store_true', dest='debug',
                        help='Enable debug 打印所有日志')
    parser.add_argument('--timeout', type=int, default=3,
                        help='超时时间')

    parser.add_argument('domain_list', nargs='?', type=argparse.FileType('r'),
                        help='指定域名列表的文件路径。')

    return parser.parse_args()


def validate_ip_address(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)  # 尝试解析 IPv4 地址
        return ip
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)  # 尝试解析 IPv6 地址
            return ip
        except socket.error:
            raise argparse.ArgumentTypeError(f"Invalid IP address: {ip}")


def expand_addresses(file_io: io.TextIOBase):
    addresses = []

    # 读取文件内容
    lines = file_io.readlines()

    # 处理每行内容
    for line in lines:
        # 去除注释和两端空格
        line = line.split('#')[0].strip()

        # 检查是否为空行
        if not line:
            continue

        # 解析 IP、IP 范围和网络掩码
        try:
            # 如果是 IP 地址
            if '/' not in line and '-' not in line:
                addresses.append(str(ipaddress.IPv4Address(line)))
            # 如果是 IP 范围
            elif '-' in line:
                start_ip, end_ip = line.split('-')
                start_ip = ipaddress.IPv4Address(start_ip.strip())
                end_ip = ipaddress.IPv4Address(end_ip.strip())
                for ip in range(int(start_ip), int(end_ip) + 1):
                    addresses.append(str(ipaddress.IPv4Address(ip)))
            # 如果是网络掩码
            else:
                network = ipaddress.IPv4Network(line, strict=False)
                for ip in network:
                    addresses.append(str(ip))
        except ValueError:
            print(f"Invalid address format: {line}")

    return addresses


# 从文件中读取域名列表
def read_domain_list(file_io: io.TextIOBase):
    domains = []
    for line in file_io:
        # 去除注释和两端空格
        line = line.split('#')[0].strip()
        if line:
            domain, record_type = line.split()
            domains.append((domain, record_type))
    return domains


# 处理单个域名的 DNS 查询
def process_domain(logger, dns_handler, dnsserver, domain_list, ecs_ip=None, src_ip=None, output_dir="output"):
    sub_response = []
    for domain, record_type in domain_list:
        response = dns_handler.dns_query(dnsserver, domain, record_type, client_ip=ecs_ip, src=src_ip)
        logger.debug(f"DNS query for {domain} from {src_ip}: {response}")
        sub_response.append(response)

    # 将查询结果写入 CSV 文件
    if src_ip and not ecs_ip:
        csv_file = os.path.join(output_dir, f"src_{src_ip}.csv")
    elif ecs_ip and not src_ip:
        csv_file = os.path.join(output_dir, f"ecs_{ecs_ip}.csv")
    elif ecs_ip and src_ip:
        csv_file = os.path.join(output_dir, f"srcAndEcs_{ecs_ip}.csv")
    else:
        csv_file = os.path.join(output_dir, f"None_{dnsserver}.csv")

    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["解析状态", "域名", "记录类型", "解析结果"])
        writer.writerows(sub_response)


# 主函数
if __name__ == "__main__":
    # 调用函数解析命令行参数
    args = parse_arguments()

    logger = setup_logger('run.log')
    if args.debug:
        logger.setLevel('DEBUG')

    # 初始化 DNSHandler 和 logger
    dns_handler = DNSHandler()
    dns_handler.query_timeout = args.timeout

    # 读取域名列表
    domain_list = read_domain_list(args.domain_list)

    # 生成不同源 IP 地址列表
    if not args.spoof_source and not args.ecs_enable:
        source_ips = ["1.1.1.1"]
    else:
        source_ips = expand_addresses(args.address_list)  # 举例

    dns_servername = args.dnsserver
    # 创建线程池
    with ThreadPoolExecutor(max_workers=args.thread) as executor:
        # 初始化进度条
        total_tasks = len(source_ips)
        progress_bar = tqdm(total=total_tasks, desc="Threads", position=0, mininterval=0.1)

        # 遍历源 IP 地址列表
        for source_ip in source_ips:
            # 创建源 IP 目录
            output_dir = os.path.join('output', dns_servername)
            os.makedirs(output_dir, exist_ok=True)
            # 将源IP和域名列表提交到线程池
            if args.spoof_source and not args.ecs_enable:  # src
                future = executor.submit(process_domain, logger, dns_handler, dns_servername, domain_list, None,
                                         source_ip, output_dir)
            elif not args.spoof_source and args.ecs_enable:  # ecs
                future = executor.submit(process_domain, logger, dns_handler, dns_servername, domain_list, source_ip,
                                         None, output_dir)
            elif args.spoof_source and args.ecs_enable:
                future = executor.submit(process_domain, logger, dns_handler, dns_servername, domain_list, source_ip,
                                         source_ip, output_dir)
            elif not args.spoof_source and not args.ecs_enable:
                future = executor.submit(process_domain, logger, dns_handler, dns_servername, domain_list, None,
                                         None, output_dir)
            # 在任务完成时更新进度条
            future.add_done_callback(lambda x: progress_bar.update())

        # 等待所有任务完成
        executor.shutdown()

        # 结束进度条
        progress_bar.close()

    # 打印空行，避免进度打印覆盖
    print()
