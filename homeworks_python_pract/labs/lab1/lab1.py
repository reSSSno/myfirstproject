import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import warnings

warnings.filterwarnings('ignore')

# ============ ЭТАП 1: ЗАГРУЗКА ДАННЫХ ============
print("=" * 50)
print("ЭТАП 1: ЗАГРУЗКА ДАННЫХ")
print("=" * 50)

# Укажите путь к вашему файлу дампа
pcap_file = '/media/sf_share/dhcp.pcapng'

# Чтение pcapng файла
print(f"Чтение файла: {pcap_file}")
capture = pyshark.FileCapture(pcap_file, display_filter='dhcp')
print("Файл успешно загружен!\n")

# ============ ЭТАП 2: ИЗВЛЕЧЕНИЕ АРТЕФАКТОВ ============
print("=" * 50)
print("ЭТАП 2: ИЗВЛЕЧЕНИЕ КЛЮЧЕВЫХ АРТЕФАКТОВ")
print("=" * 50)

# Список для хранения данных DHCP
dhcp_data = []
dns_queries = []
ip_addresses = []

# Счетчики для статистики
stats = {
    'dhcp_discover': 0,
    'dhcp_offer': 0,
    'dhcp_request': 0,
    'dhcp_ack': 0,
    'total_packets': 0
}

print("Анализ DHCP трафика...")

for packet in capture:
    stats['total_packets'] += 1

    try:
        # Извлекаем информацию из DHCP пакетов
        if hasattr(packet, 'dhcp'):
            dhcp_info = {
                'timestamp': packet.sniff_time,
                'src_mac': packet.eth.src if hasattr(packet, 'eth') else 'N/A',
                'dst_mac': packet.eth.dst if hasattr(packet, 'eth') else 'N/A',
                'src_ip': packet.ip.src if hasattr(packet, 'ip') else 'N/A',
                'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
                'message_type': packet.dhcp.option_message_type if hasattr(packet.dhcp,
                                                                           'option_message_type') else 'N/A',
                'requested_ip': packet.dhcp.option_requested_ip_address if hasattr(packet.dhcp,
                                                                                   'option_requested_ip_address') else 'N/A',
                'client_ip': packet.dhcp.option_client_ip if hasattr(packet.dhcp, 'option_client_ip') else 'N/A',
                'server_ip': packet.dhcp.option_server_ip if hasattr(packet.dhcp, 'option_server_ip') else 'N/A',
                'hostname': packet.dhcp.option_hostname if hasattr(packet.dhcp, 'option_hostname') else 'N/A',
                'lease_time': packet.dhcp.option_lease_time if hasattr(packet.dhcp, 'option_lease_time') else 'N/A'
            }

            dhcp_data.append(dhcp_info)

            # Собираем статистику по типам сообщений
            msg_type = dhcp_info['message_type']
            if msg_type == '1':
                stats['dhcp_discover'] += 1
            elif msg_type == '2':
                stats['dhcp_offer'] += 1
            elif msg_type == '3':
                stats['dhcp_request'] += 1
            elif msg_type == '5':
                stats['dhcp_ack'] += 1

            # Собираем IP адреса
            if dhcp_info['src_ip'] != 'N/A' and dhcp_info['src_ip'] not in ip_addresses:
                ip_addresses.append(dhcp_info['src_ip'])
            if dhcp_info['dst_ip'] != 'N/A' and dhcp_info['dst_ip'] not in ip_addresses:
                ip_addresses.append(dhcp_info['dst_ip'])

        # Ищем DNS запросы (если они есть)
        if hasattr(packet, 'dns'):
            dns_info = {
                'timestamp': packet.sniff_time,
                'query_name': packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else 'N/A',
                'query_type': packet.dns.qry_type if hasattr(packet.dns, 'qry_type') else 'N/A',
                'response': packet.dns.resp_name if hasattr(packet.dns, 'resp_name') else 'N/A'
            }
            dns_queries.append(dns_info)

    except AttributeError:
        continue

capture.close()

print(f"Обработано пакетов: {stats['total_packets']}")
print(f"Найдено DHCP пакетов: {len(dhcp_data)}")
print(f"Найдено DNS запросов: {len(dns_queries)}")
print(f"Уникальных IP адресов: {len(ip_addresses)}\n")

# ============ СОЗДАНИЕ DATAFRAME ============
df_dhcp = pd.DataFrame(dhcp_data)
df_dns = pd.DataFrame(dns_queries)

# Преобразуем timestamp в удобный формат
if not df_dhcp.empty:
    df_dhcp['timestamp'] = pd.to_datetime(df_dhcp['timestamp'])
    df_dhcp['time_str'] = df_dhcp['timestamp'].dt.strftime('%H:%M:%S')
    df_dhcp['date_str'] = df_dhcp['timestamp'].dt.strftime('%Y-%m-%d')

if not df_dns.empty:
    df_dns['timestamp'] = pd.to_datetime(df_dns['timestamp'])

# ============ АНАЛИЗ ПОДОЗРИТЕЛЬНОЙ АКТИВНОСТИ ============
print("=" * 50)
print("АНАЛИЗ ПОДОЗРИТЕЛЬНОЙ АКТИВНОСТИ")
print("=" * 50)

# 1. Поиск подозрительных DHCP сообщений
suspicious_dhcp = []

if not df_dhcp.empty:
    # Подозрительные хосты (если есть)
    suspicious_keywords = ['test', 'guest', 'unknown', 'admin', 'root']
    suspicious_hosts = df_dhcp[df_dhcp['hostname'].str.contains('|'.join(suspicious_keywords), case=False, na=False)]

    # Быстрые запросы аренды (возможная атака DHCP starvation)
    if len(df_dhcp) > 10:
        df_dhcp['time_diff'] = df_dhcp['timestamp'].diff().dt.total_seconds()
        rapid_requests = df_dhcp[df_dhcp['time_diff'] < 1]  # Менее 1 секунды между запросами

        if not rapid_requests.empty:
            print(f"Обнаружены быстрые DHCP запросы (<1 сек): {len(rapid_requests)}")
            suspicious_dhcp.extend(rapid_requests.to_dict('records'))

# 2. Поиск подозрительных DNS запросов
suspicious_dns = []

if not df_dns.empty:
    # Подозрительные домены
    malicious_domains = [
        'pastebin.com', 'githubusercontent.com', 'bit.ly', 'tinyurl.com',
        'drive.google.com', 'dropbox.com', 'onedrive.live.com'
    ]

    suspicious_dns_queries = df_dns[
        df_dns['query_name'].str.contains('|'.join(malicious_domains), case=False, na=False)
    ]

    if not suspicious_dns_queries.empty:
        print(f"Обнаружены запросы к подозрительным доменам: {len(suspicious_dns_queries)}")
        suspicious_dns.extend(suspicious_dns_queries.to_dict('records'))

# 3. Статистика DHCP
print("\nСтатистика DHCP сообщений:")
print(f"  DHCP Discover: {stats['dhcp_discover']}")
print(f"  DHCP Offer: {stats['dhcp_offer']}")
print(f"  DHCP Request: {stats['dhcp_request']}")
print(f"  DHCP ACK: {stats['dhcp_ack']}")

# ============ ЭТАП 3: ВИЗУАЛИЗАЦИЯ ============
print("\n" + "=" * 50)
print("ЭТАП 3: ВИЗУАЛИЗАЦИЯ РЕЗУЛЬТАТОВ")
print("=" * 50)

# Создаем фигуру для графиков
fig, axes = plt.subplots(2, 2, figsize=(15, 10))
fig.suptitle('Анализ DHCP трафика', fontsize=16)

# График 1: Распределение типов DHCP сообщений
if not df_dhcp.empty:
    ax1 = axes[0, 0]
    message_types = df_dhcp['message_type'].value_counts()
    message_types.index = message_types.index.map({
        '1': 'Discover', '2': 'Offer', '3': 'Request', '5': 'ACK'
    })
    message_types.plot(kind='bar', ax=ax1, color='skyblue')
    ax1.set_title('Распределение типов DHCP сообщений')
    ax1.set_ylabel('Количество')
    ax1.tick_params(axis='x', rotation=45)

# График 2: DHCP активность по времени
if not df_dhcp.empty and len(df_dhcp) > 1:
    ax2 = axes[0, 1]
    time_series = df_dhcp.set_index('timestamp').resample('5T').size()  # Группировка по 5 минут
    time_series.plot(ax=ax2, color='green', marker='o')
    ax2.set_title('DHCP активность по времени')
    ax2.set_ylabel('Количество пакетов')
    ax2.set_xlabel('Время')
    ax2.grid(True, alpha=0.3)

# График 3: Топ MAC адресов по активности
if not df_dhcp.empty:
    ax3 = axes[1, 0]
    top_macs = df_dhcp['src_mac'].value_counts().head(10)
    top_macs.plot(kind='bar', ax=ax3, color='orange')
    ax3.set_title('Топ-10 MAC адресов по активности')
    ax3.set_ylabel('Количество пакетов')
    ax3.tick_params(axis='x', rotation=45)

# График 4: DNS запросы по времени (если есть)
if not df_dns.empty:
    ax4 = axes[1, 1]
    dns_time_series = df_dns.set_index('timestamp').resample('1T').size()
    dns_time_series.plot(ax=ax4, color='red', marker='s')
    ax4.set_title('DNS запросы по времени')
    ax4.set_ylabel('Количество запросов')
    ax4.set_xlabel('Время')
    ax4.grid(True, alpha=0.3)
else:
    ax4 = axes[1, 1]
    ax4.text(0.5, 0.5, 'DNS запросы не найдены',
             horizontalalignment='center', verticalalignment='center',
             transform=ax4.transAxes, fontsize=12)
    ax4.set_title('DNS запросы по времени')

plt.tight_layout()
plt.savefig('dhcp_analysis_report.png', dpi=150, bbox_inches='tight')
print("Визуализация сохранена в файл: dhcp_analysis_report.png")

# ============ СОХРАНЕНИЕ РЕЗУЛЬТАТОВ ============
print("\n" + "=" * 50)
print("СОХРАНЕНИЕ РЕЗУЛЬТАТОВ")
print("=" * 50)

# Сохраняем все данные в CSV
if not df_dhcp.empty:
    df_dhcp.to_csv('dhcp_analysis.csv', index=False, encoding='utf-8')
    print("Данные DHCP сохранены в: dhcp_analysis.csv")

if not df_dns.empty:
    df_dns.to_csv('dns_analysis.csv', index=False, encoding='utf-8')
    print("Данные DNS сохранены в: dns_analysis.csv")

# Сохраняем подозрительную активность в JSON
import json

report = {
    'analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'pcap_file': pcap_file,
    'statistics': stats,
    'unique_ip_addresses': ip_addresses,
    'suspicious_activity': {
        'dhcp': suspicious_dhcp,
        'dns': suspicious_dns
    },
    'top_hostnames': df_dhcp['hostname'].value_counts().head(10).to_dict() if not df_dhcp.empty else {}
}

with open('security_analysis_report.json', 'w', encoding='utf-8') as f:
    json.dump(report, f, indent=2, default=str, ensure_ascii=False)

print("Отчет безопасности сохранен в: security_analysis_report.json")

# ============ ВЫВОД ИТОГОВОЙ ИНФОРМАЦИИ ============
print("\n" + "=" * 50)
print("ИТОГОВАЯ СВОДКА")
print("=" * 50)

print(f"1. Всего обработано пакетов: {stats['total_packets']}")
print(f"2. DHCP пакетов обнаружено: {len(dhcp_data)}")
print(f"3. DNS запросов обнаружено: {len(dns_queries)}")
print(f"4. Уникальных IP адресов: {len(ip_addresses)}")
print(f"5. Подозрительных DHCP событий: {len(suspicious_dhcp)}")
print(f"6. Подозрительных DNS запросов: {len(suspicious_dns)}")

if ip_addresses:
    print("\nУникальные IP адреса в трафике:")
    for i, ip in enumerate(ip_addresses[:10], 1):
        print(f"  {i}. {ip}")
    if len(ip_addresses) > 10:
        print(f"  ... и еще {len(ip_addresses) - 10} адресов")

if not df_dhcp.empty and 'hostname' in df_dhcp.columns:
    print("\nТоп-5 хостов по именам:")
    top_hosts = df_dhcp[df_dhcp['hostname'] != 'N/A']['hostname'].value_counts().head(5)
    for host, count in top_hosts.items():
        print(f"  • {host}: {count} запросов")

print("\nАнализ завершен! Проверьте созданные файлы:")
print("  • dhcp_analysis_report.png - визуализация")
print("  • dhcp_analysis.csv - детальные данные DHCP")
print("  • security_analysis_report.json - отчет безопасности")
