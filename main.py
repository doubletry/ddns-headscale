import subprocess 
import json
import re
import pydnspod
import yaml
import os
import sys
import logging
import time
import argparse

from logging import handlers


def parse_args():

    parser = argparse.ArgumentParser(
        description="Provide headscale ddns update service."
    )
    parser.add_argument(
        '-c',
        dest='token_file',
        help="path to generate or load config file",
        default="config.yml",
        type=str,
    )

    parser.add_argument(
        '-d',
        dest='records_file',
        help="path of record",
        default="domains.json",
        type=str,
    )

    parser.add_argument(
        "--log",
        '-l',
        dest='log_dir',
        help="path to generate log file",
        default=".",
        type=str,
    )

    return parser.parse_args()


def getLogger(path):

    logger = logging.getLogger(os.path.realpath(__file__))
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    plain_formatter = logging.Formatter(
        "[%(asctime)s][%(levelname)s] %(filename)s: %(lineno)3d: %(message)s",
        datefmt="%m/%d %H:%M:%S",
    )

    th = handlers.TimedRotatingFileHandler(filename=os.path.join(path, 'ddns-headscale.log'), when="D", backupCount=3, encoding='utf-8')#往文件里写入#指定间隔时间自动生成文件的处理器

    #实例化TimedRotatingFileHandler
    #interval是时间间隔，backupCount是备份文件的个数，如果超过这个个数，就会自动删除，when是间隔的时间单位，单位有以下几种：
    # S 秒
    # M 分
    # H 小时、
    # D 天、
    # W 每星期（interval==0时代表星期一）
    # midnight 每天凌晨

    th.setFormatter(plain_formatter)#设置文件里写入的格式
    logger.addHandler(th)
    return logger





def check_ip(ipAddr):
    compile_ip=re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if compile_ip.match(ipAddr):
        return True    
    else:    
        return False


def readYaml(yamlPath):


    if os.path.exists(yamlPath):

        with open(yamlPath, 'r', encoding='utf-8') as f:
            cfg = f.read()
        d = yaml.load(cfg, yaml.BaseLoader)
        return d, True

    else:
        d = {
            "user_id": "",
            "user_token": "",
            "domain": "",
        }
        return d, False
    

def readJson(jsonPath):


    if os.path.exists(jsonPath):

        with open(jsonPath, 'r') as f:

            domain_records = json.load(f)

        return domain_records, True

    else:
        domain_records = {
            "current_records": {},
            "deleted_records": {},
        }
        return domain_records, False


def updateRecord(handler:pydnspod.Connection, domain, prefix, ip):

    ips = handler.record.list(domain, prefix)['records']

    if len(ips) == 0:
        try:
            ret = handler.record.add(domain, prefix, "A", ip)
        except Exception as err:
            print(err, domain, prefix)
            return err

    elif ips[0]['value'] != ip:
        record_id = ips[0]['id']
        ret = handler.record.modify(domain, record_id, sub_domain=prefix,  record_type="A", value=ip)

    else:
        ret = 0

    return ret

def removeRecord(handler:pydnspod.Connection, domain, prefix):

    ips = handler.record.list(domain, prefix)['records']

    if ips:
        record_id = ips[0]['id']
        ret = handler.record.remove(domain=domain, record_id=record_id)
    
    return ret


if __name__ == "__main__":

    cfg = parse_args()
    logger = getLogger(cfg.log_dir)
    token, ret = readYaml(cfg.token_file)

    if not ret:
        with open(cfg.token_file, "w", encoding="utf-8") as f:
            yaml.dump(token, f)
        logger.info('generate config file in: {}'.format(cfg.token_file))
        sys.exit(0)

    domain_records, ret = readJson(cfg.records_file)
    
    user_id = token['user_id']
    user_token = token['user_token']
    domain = token['domain']
    dp = pydnspod.connect(user_id,user_token)

    p = subprocess.Popen("headscale node list -o json", stdout=subprocess.PIPE,shell=True)
    nodes = json.loads(p.communicate()[0].decode('utf-8'))

    tmp_current_records = {}
    for node in nodes:
        nodeName, nodeUser, nodeIP = node['given_name'], node['user']['name'], [ip for ip in node['ip_addresses'] if check_ip(ip)][0]

        sub_domain = nodeName + '.' + nodeUser
        logger.info('Updating domain: {} with ip: {}'.format(sub_domain + '.' + domain, nodeIP))
        ret = updateRecord(dp, domain, sub_domain, nodeIP)

        if ret == 0:
            logger.info('domain: {} and ip: {} not changed'.format(sub_domain + '.' + domain, nodeIP))
        else:
            logger.warning(ret)
        
        tmp_current_records['{}.{}'.format(sub_domain, domain)] = nodeIP

        sub_domain = '*' + '.' + nodeName + '.' + nodeUser
        logger.info('Updating domain: {} with ip: {}'.format(sub_domain + '.' + domain, nodeIP))
        ret = updateRecord(dp, domain, sub_domain, nodeIP)

        if ret == 0:
            logger.info('domain: {} and ip: {} not changed'.format(sub_domain + '.' + domain, nodeIP))

        else:
            logger.warning(ret)
        tmp_current_records['{}.{}'.format(sub_domain, domain)] = nodeIP

    tmp_deteled_records = {}
    for key, value in domain_records['current_records'].items():

        if key not in tmp_current_records.keys():
            prefix = '.'.join(key.split('.')[:-2])
            domain = '.'.join(key.split('.')[-2:])
            removeRecord(dp, domain, prefix)
            tmp_deteled_records[key] = value
            
    
    domain_records['current_records'] = tmp_current_records
    domain_records['deleted_records'] = tmp_deteled_records

    with open(cfg.records_file, 'w') as f:

            domain_records = json.dump(domain_records, f, indent=4)
    

        

