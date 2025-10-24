import asyncio
import aiohttp
import time
import requests
from prometheus_client import REGISTRY, Gauge, start_http_server, generate_latest, multiprocess
import prometheus_client
import logging
import json
from datetime import datetime, timedelta
import os

STORMWALL_API_KEY = os.getenv('STORMWALL_API_KEY')
STORMWALL_API_URL = "https://apiv2.stormwall.pro/v2"
COOKIES = {'api_access_token': STORMWALL_API_KEY}


L3metrics = os.getenv('L3metrics')
L7metrics = os.getenv('L7metrics')
Attacks_metrics = os.getenv('Attacks_metrics')
L3network_serviceId = os.getenv('L3network_serviceId')
L3service_serviceId = os.getenv('L3service_serviceId')
L7serviceId_str = os.getenv('L7serviceId')
# Преобразуем строку в список
L7serviceId = L7serviceId_str.split(',')
L3serviceId = [L3network_serviceId, L3service_serviceId]

print(f"L3metrics = {L3metrics}")
print(f"L7metrics = {L7metrics}")
print(f"Attacks_metrics = {Attacks_metrics}")
print(f"L3network_serviceId = {L3network_serviceId}")
print(f"L3service_serviceId = {L3service_serviceId}")
print(f"L3serviceId = {L3serviceId}")
print(f"L7serviceId = {L7serviceId}")

# Создаем метрики для Prometheus
#L3
traffic_in = Gauge('stormwall_l3_traffic_in', 'L3 Inbound traffic (bps)')
traffic_out = Gauge('stormwall_l3_traffic_out', 'L3 Outbound traffic (bps)')
percentile_in = Gauge('stormwall_l3_percentile_in', 'L3 Percentile In traffic (bps)')
percentile_out = Gauge('stormwall_l3_percentile_out', 'L3 Percentile Out traffic (bps)')
#l7
l7_traffic_out = Gauge('stormwall_l7_traffic_out', 'Outbound traffic in bps', ['domain'])
l7_traffic_cached = Gauge('stormwall_l7_traffic_cached', 'Cached traffic in bps', ['domain'])
l7_traffic_in = Gauge('stormwall_l7_traffic_in', 'Inbound traffic in bps', ['domain'])
l7_traffic_cached_bypass = Gauge('stormwall_l7_traffic_cached_bypass', 'Cached bypassed traffic in bps', ['domain'])
l7_traffic_errors_rps = Gauge('stormwall_l7_traffic_errors_rps', 'errors in rps', ['domain'])
l7_traffic_blocked_rps = Gauge('stormwall_l7_traffic_blocked_rps', 'blocked traffic in rps', ['domain'])
l7_traffic_permitted_rps = Gauge('stormwall_l7_traffic_permitted_rps', 'permitted traffic in rps', ['domain'])
l7_traffic_total_rps = Gauge('stormwall_l7_traffic_total_rps', 'total traffic in rps', ['domain'])
l7_traffic_whitelisted_rps = Gauge('stormwall_l7_traffic_whitelisted_rps', 'whitelisted traffic in rps', ['domain'])
l7_traffic_blacklisted_rps = Gauge('stormwall_l7_traffic_blacklisted_rps', 'blacklisted traffic in rps', ['domain'])
l7_traffic_cached_rps = Gauge('stormwall_l7_traffic_cached_rps', 'cached traffic in rps', ['domain'])


l7_traffic_total = Gauge('stormwall_l7_traffic_total', 'Total traffic count', ['domain'])
l7_traffic_cached_total = Gauge('stormwall_l7_traffic_cached_total', 'Total cached traffic count', ['domain'])
l7_traffic_cache_bypassed_total = Gauge('stormwall_l7_traffic_cache_bypassed_total', 'Total cache bypassed traffic count', ['domain'])
l7_traffic_total_percent = Gauge('stormwall_l7_traffic_total_percent', 'Percentage of total traffic', ['domain'])
l7_traffic_cached_percent = Gauge('stormwall_l7_traffic_cached_percent', 'Percentage of cached traffic', ['domain'])
l7_traffic_cache_bypassed_percent = Gauge('stormwall_l7_traffic_cache_bypassed_percent', 'Percentage of cache bypassed traffic', ['domain'])
l7_traffic_in_total = Gauge('stormwall_l7_traffic_in_total', 'Total inbound traffic', ['domain'])

attack_total_attacks = Gauge('stormwall_total_attacks', 'Total number of attacks')
attack_active = Gauge('stormwall_active_attacks', 'Active attacks', ['attack_target', 'attack_type'])
attack_severity = Gauge('stormwall_attack_severity', 'Severity of attacks', ['attack_target', 'severity', 'attack_type'])
attack_start_time = Gauge('stormwall_attack_start_time', 'Timestamp when the attack started', ['attack_target', 'attack_type'])

prometheus_client.REGISTRY.unregister(prometheus_client.PROCESS_COLLECTOR)
prometheus_client.REGISTRY.unregister(prometheus_client.PLATFORM_COLLECTOR)
prometheus_client.REGISTRY.unregister(prometheus_client.GC_COLLECTOR)





def collect_domains_id():
    #if L7metrics == 'enable' :
        domains_data = {}
        # Выполняем функцию для каждого ID и сохраняем результаты в словарь
        for service_id in L7serviceId:
            domains_data[service_id] = get_domains_id(service_id)

            # Печать данных для каждого service_id
        for service_id, data in domains_data.items():
            logging.debug(f"Data for service ID {service_id}: {data}")
        return domains_data

def get_domains_id(service_id):
    url = f"https://api.stormwall.pro/user/service/{service_id}/domain-list"
    try:
            response = requests.get(url, cookies=COOKIES)
            response.raise_for_status()  # Проверяем успешный ответ
            data = response.json()
            domains = [{"domain_id": domain["domain_id"], "domain_name": domain["domain_name"]} for domain in data["list"]]
            return domains
    except requests.exceptions.RequestException as e:
            print(f"Error fetching traffic data: {e}")
            return None

def get_url(serviceId, layer, metric_url, domain_id, type, units):
    fromTime = (int((datetime.now() - timedelta(minutes=7)).timestamp()) * 1000 )
    toTime = (int((datetime.now() - timedelta(minutes=4)).timestamp()) * 1000 )

    url = f"{STORMWALL_API_URL}/{serviceId}/{layer}{metric_url}"

    if layer == 'l7/' and domain_id != 0 :
                url = f"{STORMWALL_API_URL}/{serviceId}/{layer}{domain_id}/{metric_url}"
    if layer != 'l3/' and layer != '' and layer != 'l7/':
        url += f"?fromTime={fromTime}&toTime={toTime}&units={units}" #ko
        if (metric_url == 'chart' or 'traffic') and layer != 'l7/' :
            url += f"&type={type}"
    if layer == 'l7/' :
                url += f"?fromTime={fromTime}&toTime={toTime}&units={units}"
                if (metric_url == 'chart' or 'traffic') and layer != 'l7/' :
                            url += f"&type={type}"
    if metric_url == 'percentile' and layer != 'l7/' :
        url = f"{STORMWALL_API_URL}/{serviceId}/{layer}{metric_url}?toTime={toTime}"
    if metric_url == 'percentile' and layer == 'l7/' :
        url = f"{STORMWALL_API_URL}/{serviceId}/{layer}network-protection/{metric_url}?toTime={toTime}"

    if metric_url == 'attacks' :
        url = f"{STORMWALL_API_URL}/"
        if layer == '' :
            url += f"{metric_url}?startTime={fromTime}&stopTime={toTime}&limit=100&offset=0&addActive=true"
        else:
            url += f"{serviceId}/{layer}"
            if layer == 'l7/':
                url += f"{domain_id}/"
            url += f"{metric_url}?startTime={fromTime}&stopTime={toTime}&limit=100&offset=0&addActive=true"
    #print(f"__url__:{url}")
    return url

async def get_L3_data():
    L3_data = []
    metrics = ['traffic']  # Можно добавить другие метрики по мере необходимости

    # Для асинхронной работы с API
    async with aiohttp.ClientSession() as session:
        tasks = []  # Список задач для асинхронного выполнения
        units = "bps"

        # Запускаем все запросы параллельно
        url = get_url(L3network_serviceId, 'l3/network-protection/', 'percentile', 0, 0, units)
        tasks.append(fetch_L3_data(session, url, 'percentile', 0, units, L3_data))
        for metric in metrics:
            for type in ("Out", "In"):
                #for units in ("bps"):  # Можно добавить другие, если нужно

                    url = get_url(L3network_serviceId, 'l3/network-protection/', metric, 0, type, units)

                    # Для каждого запроса создаем задачу
                    tasks.append(fetch_L3_data(session, url, metric, type, units, L3_data))

        # Ждем выполнения всех задач
        await asyncio.gather(*tasks)

    return L3_data  # Возвращаем результаты

# Асинхронная версия для обработки одного запроса
async def fetch_L3_data(session, url, metric, type, units, L3_data):
    try:
        async with session.get(url, cookies=COOKIES) as response:
            response.raise_for_status()  # Проверяем успешный статус ответа
            if response.status == 200:
                data = await response.json()  # Получаем данные асинхронно
            else:
                data = None
                logging.error(f"Error response: {await response.json()}")

            if data:
                #print(f"L3_data:\n\n{data}")
                result_data = []

                # Для метрики traffic извлекаем значения 'value' из списка traffic
                if 'objects' in data:
                    for obj in data['objects']:
                        for traffic in obj.get('traffic', []):
                            result_data.append(traffic.get('value'))  # Добавляем значение 'value'

                # Для метрики percentile извлекаем значения 'in' и 'out'
                if 'percentile' in data:
                    if 'in' in data['percentile']:
                        result_data.append(data['percentile']['in'])  # Добавляем значение 'in'
                    if 'out' in data['percentile']:
                        result_data.append(data['percentile']['out'])  # Добавляем значение 'out'


                # Добавляем обработанные данные в L3_data
                L3_data.append({
                    "metric": metric,
                    "type": type,
                    "units": units,
                    "data": result_data
                })
            else:
                # Если данных нет, добавляем пустое значение
                L3_data.append({
                    "metric": metric,
                    "type": type,
                    "units": units,
                    "data": None
                })

    except aiohttp.ClientError as e:
        logging.error(f"Error fetching data from Stormwall API for {metric}, {type}, {units} with URL {url}: {e}")
        # Даже в случае ошибки, добавляем запись в список
        L3_data.append({
            "metric": metric,
            "type": type,
            "units": units,
            "data": None
        })

# Для асинхронной работы с API
async def fetch_data(session, url):
    try:
        async with session.get(url, cookies=COOKIES) as response:
            response.raise_for_status()
            return await response.json()
    except aiohttp.ClientError as e:
        logging.error(f"Error fetching data from Stormwall API. URL: {url}, Error: {e}")
        return None

# Асинхронная версия L7_function
async def L7_function(L7_data, serviceId, metric, domainId, domainName, session):
    #units = "bps"
    unitss = ['bps', 'rps']
    for units in unitss:
     url = get_url(serviceId, 'l7/', metric, domainId, 0, units)
     #print(f"L7_domain - {domainName}")

     data = await fetch_data(session, url)
     if data:
        if domainName not in L7_data:
            L7_data[domainName] = []

        #print(f"data for {domainName}:\n {data}")

        # Список для хранения данных домена
        domain_data = {}

        # Обработка трафика
        traffic = data.get('traffic', [])
        if traffic:
          if units == 'bps':
            traffic_info = {
                "traffic_out": traffic[0].get('out', 'N/A'),
                "traffic_cached": traffic[0].get('cached', 'N/A'),
                "traffic_in": traffic[0].get('in', 'N/A'),
                "traffic_cached_bypass": traffic[0].get('cached_bypass', 'N/A')
            }
            domain_data['traffic'] = traffic_info
            #print(f"L7_traffic for {domainName}: {traffic_info}")
          if units == 'rps':
            traffic_info_rps = {
                "traffic_errors_rps": traffic[0].get('errors', '0'),
                "traffic_blocked_rps": traffic[0].get('blocked', '0'),
                "traffic_permitted_rps": traffic[0].get('permitted', '0'),
                "traffic_total_rps": traffic[0].get('total', '0'),
                "traffic_whitelisted_rps": traffic[0].get('whitelisted', '0'),
                "traffic_blacklisted_rps": traffic[0].get('blacklisted', '0'),
                "traffic_cached_rps": traffic[0].get('cached', '0')
            }
            domain_data['traffic_rps'] = traffic_info_rps
            #print(f"L7_traffic for {domainName}: {traffic_info}")

        # Обработка счетчиков
        if units == 'bps':
         counters = data.get('counters', {})
         counters_info = {
            "traffic_total": counters.get('traffic_total', 'N/A'),
            "traffic_cached": counters.get('traffic_cached', 'N/A'),
            "traffic_cache_bypassed": counters.get('traffic_cache_bypassed', 'N/A'),
            "traffic_total_percent": counters.get('traffic_total_percent', 'N/A'),
            "traffic_cached_percent": counters.get('traffic_cached_percent', 'N/A'),
            "traffic_cache_bypassed_percent": counters.get('traffic_cache_bypassed_percent', 'N/A'),
            "traffic_in_total": counters.get('traffic_in_total', 'N/A')
         }
         domain_data['counters'] = counters_info
        #print(f"L7_counters for {domainName}: {counters_info}")

        # Добавляем данные в L7_data
        L7_data[domainName].append(domain_data)

# Асинхронная версия get_L7_data
async def get_L7_data(domains_data):
    L7_data = {}

    async with aiohttp.ClientSession() as session:
        tasks = []
        for serviceId in L7serviceId:
            tasks.append(L7_function(L7_data, serviceId, 'percentile', 0, 'percentile', session))
            for domain in domains_data.get(serviceId, []):
                domainId = domain['domain_id']
                domainName = domain['domain_name']
                tasks.append(L7_function(L7_data, serviceId, 'traffic', domainId, domainName, session))

        # Запускаем все задачи параллельно
        ##await asyncio.gather(*tasks)
        resultss = []
        for i, task in enumerate(tasks):
            if i > 0:  # Не добавляем задержку перед первой задачей
                await asyncio.sleep(0.5)  # Ждем 1 секунду перед запуском следующей задачи
            resultss.append(await task)  # Выполняем задачу и сохраняем результат

    #print(f"L7_data: {L7_data}")
    return L7_data

async def attacks_function(serviceId, layer, domain_id, attacks_data):
    try:
        # Проверяем, если передан словарь с ключом 'domain_id', то извлекаем значение
        domainId = domain_id.get('domain_id') if isinstance(domain_id, dict) else domain_id
        domain = domain_id.get('domain_name') if isinstance(domain_id, dict) else 0
        if domain_id == 0:
            domainId = 0
            domain = 'all_attacks'
        #print(f"try domainId_____: {domainId} -- {domain}")
    except KeyError as e:
        logging.error(f"KeyError: Missing key in domain_id: {e} for domain_id: {domain_id}")
        domainId = domain_id  # В случае ошибки просто присваиваем значение как есть
        domain = domain_id  # Если возникла ошибка, пытаемся использовать domain_id как есть
        print(f"except domainId_____: {domainId} -- {domain}")
        logging.error(f"Falling back to domainId: {domainId}")

    # Формируем URL
    url = get_url(serviceId, layer, 'attacks', domainId, 0, 0)

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, cookies=COOKIES) as response:
                response.raise_for_status()
                if response.status == 200:
                    data = await response.json()  # Получаем JSON-ответ асинхронно
                    total_attacks = data.get('total', 0)  # Сохраняем общее количество атак
                    for attack in data.get('result', []):
                        # Сохраняем информацию по атаке
                        if domain not in attacks_data:
                            attacks_data[domain] = []  # Инициализация списка для домена, если ещё нет

                        attack_info = {
                            'attack_total_attacks': total_attacks,  # Общее количество атак
                            'attack_target': attack.get('target', 'N/A'),  # Цель атаки
                            'attack_type': attack.get('type', 'N/A'),  # Тип атаки
                            'attack_start_time': attack.get('start_time', 'N/A'),  # Время начала
                            'attack_active': attack.get('active', False),  # Статус активности
                            'attack_severity': attack.get('severity', 'N/A')  # Серьезность
                        }

                        # Добавляем информацию об атаке в список для этого домена
                        attacks_data[domain].append(attack_info)
                        #print(f"attacks_data for {domain}: {attacks_data[domain]}")
                else:
                    logging.error(f"Error in response: {response.status}, {await response.json()}")
        except aiohttp.ClientError as e:
            logging.error(f"Error fetching data from Stormwall API for {serviceId}, {layer}, {domainId}, URL: {url}, Error: {e}")

# Обертка для запуска нескольких асинхронных задач
async def get_attacks_data(domains_data):
    tasks = []
    attacks_data = {}
    await attacks_function('', '', 0, attacks_data)
    #tasks.append(attacks_function('', '', 0, attacks_data))
    # Лишнее
    #for service_id in L7serviceId:
    #        print(f"domains_data[service_id]: {domains_data[service_id]}")
    #        print(f"service_id: {service_id}")
    #        for domainId in domains_data[service_id]:
    #        #for domainId in domains_data.get(service_id, []):
    #            #print(f"L7domainId_____: {domainId}")
    #            tasks.append(attacks_function(service_id, 'l7/', domainId, attacks_data))
    #            #attacks_function(service_id, 'l7/', domainId, attacks_data)
    for service_id in L3serviceId:
                #print(f"L3domainId_____: {domainId}")
                #attacks_function(service_id, 'l3/', 0, attacks_data)
                tasks.append(attacks_function(service_id, 'l3/', 0, attacks_data))

    # Выполняем все задачи параллельно
    await asyncio.gather(*tasks)

    return attacks_data

def safe_float(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0

# Обновление метрик с асинхронным вызовом
async def update_metrics():

    if L3metrics == 'enable':
        L3_data = await get_L3_data()
        #print(f"L3_data->: {L3_data}")
        for metric_data in L3_data:
                metric = metric_data['metric']
                type = metric_data['type']
                data = metric_data['data']
                if data is not None and len(data) > 0:
                # Если это метрика для входящего трафика (In)
                  if metric == 'traffic' and type == 'In':
                    traffic_in.set(safe_float(data[0]))
                    #print(f"traffic_in: {data} -> {data[-1]}")

                # Если это метрика для исходящего трафика (Out)
                  elif metric == 'traffic' and type == 'Out':
                       traffic_out.set(safe_float(data[0]))
                    #print(f"traffic_out: {data} -> {data[-1]}")

                # Если это метрика для percentile In
                  elif metric == 'percentile':
                    percentile_in.set(safe_float(data[0]))  # Используем первое значение
                    #print(f"percentile_in: {data} -> {data[0]}")
                    percentile_out.set(safe_float(data[1]))  # Используем второе значение
                    #print(f"percentile_out: {data} -> {data[1]}")
    time.sleep(15)
    if L7metrics == 'enable':
        # Асинхронно получаем L7 данные
        L7_data = await get_L7_data(domains_data)

        for domain, domain_data in L7_data.items():
                for data in domain_data:
                    # Получаем данные о трафике
                    traffic = data.get('traffic', {})
                    if traffic:
                        l7_traffic_out.labels(domain=domain).set(safe_float(traffic.get('traffic_out', 0)))
                        l7_traffic_cached.labels(domain=domain).set(safe_float(traffic.get('traffic_cached', 0)))
                        l7_traffic_in.labels(domain=domain).set(safe_float(traffic.get('traffic_in', 0)))
                        l7_traffic_cached_bypass.labels(domain=domain).set(safe_float(traffic.get('traffic_cached_bypass', 0)))
                    
                    traffic_rps = data.get('traffic_rps', {})
                    if traffic_rps:
                        l7_traffic_errors_rps.labels(domain=domain).set(safe_float(traffic_rps.get('traffic_errors_rps', 0)))
                        l7_traffic_blocked_rps.labels(domain=domain).set(safe_float(traffic_rps.get('traffic_blocked_rps', 0)))
                        l7_traffic_permitted_rps.labels(domain=domain).set(safe_float(traffic_rps.get('traffic_permitted_rps', 0)))
                        l7_traffic_total_rps.labels(domain=domain).set(safe_float(traffic_rps.get('traffic_total_rps', 0)))
                        l7_traffic_whitelisted_rps.labels(domain=domain).set(safe_float(traffic_rps.get('traffic_whitelisted_rps', 0)))
                        l7_traffic_blacklisted_rps.labels(domain=domain).set(safe_float(traffic_rps.get('traffic_blacklisted_rps', 0)))
                        l7_traffic_cached_rps.labels(domain=domain).set(safe_float(traffic_rps.get('traffic_cached_rps', 0)))
                        

                    # Получаем данные счетчиков
                    counters = data.get('counters', {})
                    if counters:
                        l7_traffic_total.labels(domain=domain).set(safe_float(counters.get('traffic_total', 0)))
                        l7_traffic_cached_total.labels(domain=domain).set(safe_float(counters.get('traffic_cached', 0)))
                        l7_traffic_cache_bypassed_total.labels(domain=domain).set(safe_float(counters.get('traffic_cache_bypassed', 0)))
                        l7_traffic_total_percent.labels(domain=domain).set(safe_float(counters.get('traffic_total_percent', 0)))
                        l7_traffic_cached_percent.labels(domain=domain).set(safe_float(counters.get('traffic_cached_percent', 0)))
                        l7_traffic_cache_bypassed_percent.labels(domain=domain).set(safe_float(counters.get('traffic_cache_bypassed_percent', 0)))
                        l7_traffic_in_total.labels(domain=domain).set(safe_float(counters.get('traffic_in_total', 0)))
    time.sleep(15)
    if Attacks_metrics == 'enable':
        attacks_data = await get_attacks_data(domains_data)
        # print(f"attacks_data:\n{attacks_data}")
        for attack in attacks_data['all_attacks']:
            # Получаем домен из attack_target
            attack_target = attack['attack_target']

            # Total attacks
            attack_total_attacks.set(attack['attack_total_attacks'])
            #print(f"total attacks for {attack_target}: {attack['attack_total_attacks']}")

            # Active attacks
            active_value = 1 if attack['attack_active'] else 0
            attack_active.labels(attack_target=attack_target, attack_type=attack['attack_type']).set(active_value)
            #print(f"active attacks for {attack_target}: {active_value}")

            # Attack severity
            severity_value = 0  # Значение по умолчанию, если severity не совпадает
            if attack['attack_severity'] == 'low':
                severity_value = 1
            elif attack['attack_severity'] == 'middle':
                severity_value = 2
            elif attack['attack_severity'] == 'high':
                severity_value = 3
            else:
                severity_value = 0

            # Теперь передаем severity_value в метрику
            attack_severity.labels(attack_target=attack_target, severity=attack['attack_severity'], attack_type=attack['attack_type']).set(severity_value)
            #print(f"Attack severity for {attack_target} - {attack['attack_severity']} (set value: {severity_value})")

            # Attack start time
            attack_start_time.labels(attack_target=attack_target, attack_type=attack['attack_type']).set(attack['attack_start_time'])
            #print(f"attack start time for {attack_target} - {attack['attack_type']}: {attack['attack_start_time']}")
    time.sleep(15)

if __name__ == "__main__":
    domains_data = collect_domains_id()
    start_http_server(9031)
    print("Exporter is running on http://localhost:9031")
    while True:
            asyncio.run(update_metrics())
            time.sleep(60)
