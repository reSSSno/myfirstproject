"""
Автоматизированный мониторинг и реагирование на угрозы
Использует данные из VirusTotal API и локальных логов Suricata
"""

import requests
import pandas as pd
import json
import matplotlib.pyplot as plt
from datetime import datetime
import os
import time
from collections import Counter
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

# Конфигурация
class Config:
    # VirusTotal API ключ (обязательно нужно заменить на свой)
    VIRUSTOTAL_API_KEY = "ВАШ_API_КЛЮЧ"  # Замените на свой реальный ключ
    
    # Пути к файлам
    SURICATA_LOG_PATH = "suricata_logs/suricata_eve.json"
    OUTPUT_REPORT_PATH = "threat_report.json"
    OUTPUT_CSV_PATH = "threat_report.csv"
    OUTPUT_GRAPH_PATH = "threat_analysis.png"
    
    # Пороговые значения для обнаружения угроз
    SUSPICIOUS_IPS = []  # Добавьте подозрительные IP для проверки
    CVSS_THRESHOLD = 7.0  # Порог для высокоуровневых уязвимостей
    DNS_QUERY_THRESHOLD = 100  # Порог для подозрительного количества DNS запросов
    
    # Настройки API
    VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
    VIRUSTOTAL_REQUEST_DELAY = 15  # Задержка между запросами (API лимит)

class ThreatMonitor:
    def __init__(self, config):
        self.config = config
        self.threats_found = []
        self.ip_reputation = {}
        
    def check_virustotal_ip(self, ip_address):
        """Проверка IP-адреса через VirusTotal API"""
        
        if not self.config.VIRUSTOTAL_API_KEY or self.config.VIRUSTOTAL_API_KEY == "ВАШ_API_КЛЮЧ_ЗДЕСЬ":
            print("ОШИБКА: Не установлен API ключ VirusTotal.")
            print("Пожалуйста, получите API ключ на https://www.virustotal.com/ и установите его в конфигурации.")
            return None
        
        print(f"Проверка IP {ip_address} через VirusTotal API...")
        
        url = f"{self.config.VIRUSTOTAL_API_URL}{ip_address}"
        headers = {
            "x-apikey": self.config.VIRUSTOTAL_API_KEY,
            "accept": "application/json"
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                reputation = attributes.get('reputation', 0)
                
                malicious = last_analysis_stats.get('malicious', 0)
                suspicious = last_analysis_stats.get('suspicious', 0)
                undetected = last_analysis_stats.get('undetected', 0)
                harmless = last_analysis_stats.get('harmless', 0)
                
                status = "clean"
                if malicious > 3:
                    status = "malicious"
                elif malicious > 0 or suspicious > 2:
                    status = "suspicious"
                elif reputation < 0:
                    status = "suspicious"
                
                result = {
                    "ip": ip_address,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "undetected": undetected,
                    "harmless": harmless,
                    "reputation": reputation,
                    "status": status,
                    "total_engines": malicious + suspicious + undetected + harmless
                }
                
                print(f"  Результат: {status} (зловредных: {malicious}, подозрительных: {suspicious})")
                return result
                
            elif response.status_code == 404:
                print(f"  IP {ip_address} не найден в базе VirusTotal")
                return {
                    "ip": ip_address,
                    "status": "not_found",
                    "malicious": 0,
                    "suspicious": 0
                }
                
            elif response.status_code == 429:
                print("  Превышен лимит запросов к VirusTotal API. Ожидание...")
                time.sleep(60)  # Ожидаем 60 секунд при превышении лимита
                return None
                
            else:
                print(f"  Ошибка API: {response.status_code} - {response.text[:100]}")
                return None
                
        except requests.exceptions.Timeout:
            print("  Таймаут при запросе к VirusTotal")
            return None
        except requests.exceptions.ConnectionError:
            print("  Ошибка подключения к VirusTotal")
            return None
        except Exception as e:
            print(f"  Ошибка при запросе к VirusTotal: {str(e)[:100]}")
            return None
    
    def parse_suricata_logs(self):
        """Парсинг логов Suricata"""
        
        logs = []
        
        # Проверяем существование файла логов
        if os.path.exists(self.config.SURICATA_LOG_PATH):
            try:
                print(f"Чтение логов Suricata из {self.config.SURICATA_LOG_PATH}")
                with open(self.config.SURICATA_LOG_PATH, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line:
                            try:
                                log_entry = json.loads(line)
                                
                                # Проверяем обязательные поля для анализа
                                if any(key in log_entry for key in ['src_ip', 'dest_ip', 'alert', 'dns']):
                                    logs.append(log_entry)
                            except json.JSONDecodeError as e:
                                print(f"  Ошибка JSON в строке {line_num}: {str(e)[:50]}")
                                continue
                print(f"  Загружено {len(logs)} записей из логов Suricata")
                
            except Exception as e:
                print(f"  Ошибка чтения логов Suricata: {e}")
                return []
        else:
            print(f"  Файл логов не найден: {self.config.SURICATA_LOG_PATH}")
            print("  Пожалуйста, укажите правильный путь к файлу логов Suricata.")
            return []
        
        return logs
    
    def analyze_logs(self, logs):
        """Анализ логов на наличие угроз"""
        
        if not logs:
            print("  Нет логов для анализа")
            return []
        
        threats = []
        
        # Собираем статистику по IP-адресам
        src_ips = []
        dns_queries = {}
        
        for log in logs:
            src_ip = log.get('src_ip')
            if src_ip:
                src_ips.append(src_ip)
            
            # Считаем DNS запросы
            if log.get('event_type') == 'dns':
                dns_info = log.get('dns', {})
                if src_ip and dns_info.get('rrname'):
                    if src_ip not in dns_queries:
                        dns_queries[src_ip] = 0
                    dns_queries[src_ip] += 1
        
        # Анализируем частые DNS запросы
        for ip, count in dns_queries.items():
            if count > self.config.DNS_QUERY_THRESHOLD:
                threat = {
                    "type": "dns_flood",
                    "ip": ip,
                    "reason": f"Подозрительно много DNS запросов ({count} > {self.config.DNS_QUERY_THRESHOLD})",
                    "timestamp": datetime.now().isoformat(),
                    "severity": "medium"
                }
                threats.append(threat)
                print(f"  Обнаружена угроза: DNS flood от IP {ip} ({count} запросов)")
        
        # Анализируем алерты Suricata
        for log in logs:
            if log.get('event_type') == 'alert':
                alert = log.get('alert', {})
                src_ip = log.get('src_ip')
                signature = alert.get('signature', 'Unknown')
                severity = alert.get('severity', 0)
                
                if severity >= 1 and src_ip:
                    threat = {
                        "type": "suricata_alert",
                        "ip": src_ip,
                        "signature": signature,
                        "reason": f"Обнаружена подозрительная активность: {signature}",
                        "timestamp": log.get('timestamp', datetime.now().isoformat()),
                        "severity": "high" if severity >= 2 else "medium"
                    }
                    threats.append(threat)
                    print(f"  Обнаружена угроза: Suricata alert от IP {src_ip} - {signature}")
        
        # Проверяем подозрительные IP из конфигурации
        for suspicious_ip in self.config.SUSPICIOUS_IPS:
            if suspicious_ip in src_ips:
                threat = {
                    "type": "suspicious_ip",
                    "ip": suspicious_ip,
                    "reason": "IP находится в списке подозрительных",
                    "timestamp": datetime.now().isoformat(),
                    "severity": "high"
                }
                threats.append(threat)
                print(f"  Обнаружена угроза: Подозрительный IP {suspicious_ip}")
        
        return threats
    
    def scan_vulnerabilities(self):
        """Сканирование уязвимостей (имитация на основе статических данных)"""
        
        print("Сканирование на наличие уязвимостей...")
        
        # Статические данные об уязвимостях (имитация)
        vulnerabilities = [
            {
                "cve_id": "CVE-2021-44228",
                "description": "Log4Shell RCE уязвимость в Apache Log4j",
                "cvss_score": 10.0,
                "severity": "critical",
                "affected_software": "Apache Log4j 2.0-beta9 до 2.15.0",
                "detected_in": "web-server-01"
            },
            {
                "cve_id": "CVE-2021-34527",
                "description": "PrintNightmare LPE уязвимость",
                "cvss_score": 8.8,
                "severity": "high",
                "affected_software": "Windows Print Spooler",
                "detected_in": "workstation-05"
            },
            {
                "cve_id": "CVE-2017-0144",
                "description": "EternalBlue SMB RCE уязвимость",
                "cvss_score": 8.5,
                "severity": "high",
                "affected_software": "Windows SMBv1",
                "detected_in": "file-server-02"
            }
        ]
        
        threats = []
        for vuln in vulnerabilities:
            if vuln['cvss_score'] >= self.config.CVSS_THRESHOLD:
                threat = {
                    "type": "vulnerability",
                    "cve_id": vuln["cve_id"],
                    "description": vuln["description"],
                    "cvss_score": vuln["cvss_score"],
                    "affected_system": vuln.get("detected_in", "unknown"),
                    "reason": f"Обнаружена {vuln['severity']} уязвимость: {vuln['description']}",
                    "severity": vuln["severity"]
                }
                threats.append(threat)
                print(f"  Обнаружена уязвимость: {vuln['cve_id']} (CVSS: {vuln['cvss_score']}) - {vuln['severity']}")
        
        return threats
    
    def respond_to_threat(self, threat):
        """Реагирование на обнаруженные угрозы"""
        
        response_actions = []
        
        if threat["type"] in ["suspicious_ip", "dns_flood", "virustotal_malicious"]:
            # Блокировка подозрительного IP
            action = {
                "action": "block_ip",
                "target": threat["ip"],
                "message": f"IP адрес {threat['ip']} заблокирован в межсетевом экране",
                "timestamp": datetime.now().isoformat(),
                "details": {
                    "reason": threat.get("reason", "Подозрительная активность"),
                    "severity": threat.get("severity", "medium")
                }
            }
            response_actions.append(action)
            print(f"  [ДЕЙСТВИЕ] Блокировка IP: {threat['ip']}")
            
        elif threat["type"] == "vulnerability":
            # Применение исправлений для уязвимости
            action = {
                "action": "apply_patch",
                "target": threat["cve_id"],
                "message": f"Инициировано применение патча для {threat['cve_id']}",
                "timestamp": datetime.now().isoformat(),
                "details": {
                    "description": threat.get("description", ""),
                    "cvss_score": threat.get("cvss_score", 0),
                    "affected_system": threat.get("affected_system", "unknown")
                }
            }
            response_actions.append(action)
            print(f"  [ДЕЙСТВИЕ] Патч для уязвимости: {threat['cve_id']}")
            
        elif threat["type"] == "suricata_alert":
            # Изоляция системы и расследование
            action = {
                "action": "isolate_and_investigate",
                "target": threat["ip"],
                "message": f"Система с IP {threat['ip']} изолирована для расследования",
                "timestamp": datetime.now().isoformat(),
                "details": {
                    "signature": threat.get("signature", "Unknown"),
                    "reason": threat.get("reason", "Обнаружена подозрительная активность")
                }
            }
            response_actions.append(action)
            print(f"  [ДЕЙСТВИЕ] Изоляция системы: {threat['ip']}")
            
        # Всегда отправляем уведомление администратору. В поле target необходимо подставить свой mail.
        notification = {
            "action": "notify_security_team",
            "target": "megashark11@mail.ru",
            "message": f"Обнаружена угроза безопасности: {threat['type']} - {threat.get('reason', '')}",
            "timestamp": datetime.now().isoformat(),
            "details": {
                "threat_type": threat["type"],
                "severity": threat.get("severity", "unknown"),
                "timestamp": threat.get("timestamp", datetime.now().isoformat())
            }
        }
        response_actions.append(notification)
        print(f"  [УВЕДОМЛЕНИЕ] Отправлено security team")
        
        return response_actions
    
    def generate_report(self, threats, responses):
        """Генерация отчета"""
        
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool_version": "1.0",
                "scan_duration_seconds": int(time.time() - self.start_time)
            },
            "summary": {
                "total_threats": len(threats),
                "critical_threats": len([t for t in threats if t.get('severity') == 'critical']),
                "high_threats": len([t for t in threats if t.get('severity') == 'high']),
                "medium_threats": len([t for t in threats if t.get('severity') == 'medium']),
                "low_threats": len([t for t in threats if t.get('severity') == 'low']),
                "actions_taken": len(responses)
            },
            "threats_detected": threats,
            "response_actions": responses,
            "recommendations": self.generate_recommendations(threats)
        }
        
        # Сохранение отчета в JSON
        try:
            with open(self.config.OUTPUT_REPORT_PATH, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"  JSON отчет сохранен в {self.config.OUTPUT_REPORT_PATH}")
        except Exception as e:
            print(f"  Ошибка сохранения JSON отчета: {e}")
        
        # Сохранение отчета в CSV
        try:
            if threats:
                df_threats = pd.DataFrame(threats)
                df_threats.to_csv(self.config.OUTPUT_CSV_PATH, index=False, encoding='utf-8')
                print(f"  CSV отчет сохранен в {self.config.OUTPUT_CSV_PATH}")
        except Exception as e:
            print(f"  Ошибка сохранения CSV отчета: {e}")
        
        return report
    
    def generate_recommendations(self, threats):
        """Генерация рекомендаций по устранению угроз"""
        
        recommendations = []
        
        if any(t['type'] == 'vulnerability' for t in threats):
            recommendations.append({
                "priority": "high",
                "recommendation": "Применить критические обновления безопасности",
                "details": "Обновите ПО для устранения обнаруженных уязвимостей"
            })
        
        if any(t['type'] in ['suspicious_ip', 'virustotal_malicious'] for t in threats):
            recommendations.append({
                "priority": "high",
                "recommendation": "Усилить мониторинг сетевой активности",
                "details": "Добавить правила в IDS/IPS для обнаружения подозрительных IP"
            })
        
        if any(t['type'] == 'dns_flood' for t in threats):
            recommendations.append({
                "priority": "medium",
                "recommendation": "Настроить ограничения на DNS запросы",
                "details": "Установить лимиты на частоту DNS запросов с одного IP"
            })
        
        if not recommendations:
            recommendations.append({
                "priority": "info",
                "recommendation": "Провести регулярное аудирование безопасности",
                "details": "Рекомендуется периодическая проверка систем на уязвимости"
            })
        
        return recommendations
    
    def visualize_results(self, threats, logs):
        """Визуализация результатов анализа"""
        
        if not threats and not logs:
            print("  Нет данных для визуализации")
            return
        
        try:
            fig, axes = plt.subplots(2, 2, figsize=(15, 10))
            fig.suptitle('Анализ угроз безопасности', fontsize=16, fontweight='bold')
            
            # 1. Распределение типов угроз
            if threats:
                threat_types = [t['type'] for t in threats]
                type_counts = Counter(threat_types)
                
                if type_counts:
                    ax1 = axes[0, 0]
                    bars = ax1.bar(range(len(type_counts)), list(type_counts.values()))
                    ax1.set_title('Типы обнаруженных угроз')
                    ax1.set_xlabel('Тип угрозы')
                    ax1.set_ylabel('Количество')
                    ax1.set_xticks(range(len(type_counts)))
                    ax1.set_xticklabels(list(type_counts.keys()), rotation=45, ha='right')
                    
                    # Добавляем значения на столбцы
                    for bar in bars:
                        height = bar.get_height()
                        ax1.text(bar.get_x() + bar.get_width()/2., height,
                                f'{int(height)}', ha='center', va='bottom')
            
            # 2. Уровни серьезности угроз
            if threats:
                severities = [t.get('severity', 'unknown') for t in threats]
                severity_counts = Counter(severities)
                
                if severity_counts:
                    ax2 = axes[0, 1]
                    
                    # Цвета для уровней серьезности
                    severity_order = ['critical', 'high', 'medium', 'low', 'unknown']
                    colors = {'critical': '#FF0000', 'high': '#FF6B00', 'medium': '#FFD700', 
                             'low': '#90EE90', 'unknown': '#CCCCCC'}
                    
                    sorted_severities = []
                    sorted_counts = []
                    sorted_colors = []
                    
                    for severity in severity_order:
                        if severity in severity_counts:
                            sorted_severities.append(severity)
                            sorted_counts.append(severity_counts[severity])
                            sorted_colors.append(colors.get(severity, '#CCCCCC'))
                    
                    wedges, texts, autotexts = ax2.pie(sorted_counts, labels=sorted_severities, 
                                                      autopct='%1.1f%%', colors=sorted_colors,
                                                      startangle=90)
                    ax2.set_title('Уровни серьезности угроз')
                    
                    # Делаем подписи более читаемыми
                    for text in texts:
                        text.set_fontsize(10)
                    for autotext in autotexts:
                        autotext.set_fontsize(9)
            
            # 3. Топ-5 IP-адресов по событиям
            if logs:
                src_ips = [log.get('src_ip') for log in logs if log.get('src_ip')]
                if src_ips:
                    ip_counts = Counter(src_ips)
                    top_ips = dict(ip_counts.most_common(5))
                    
                    if top_ips:
                        ax3 = axes[1, 0]
                        bars = ax3.bar(range(len(top_ips)), list(top_ips.values()))
                        ax3.set_title('Топ-5 IP-адресов по активности')
                        ax3.set_xlabel('IP-адрес')
                        ax3.set_ylabel('Количество событий')
                        ax3.set_xticks(range(len(top_ips)))
                        ax3.set_xticklabels(list(top_ips.keys()), rotation=45, ha='right')
            
            # 4. Распределение событий по типам (из логов)
            if logs:
                event_types = [log.get('event_type', 'unknown') for log in logs]
                if event_types:
                    event_counts = Counter(event_types)
                    
                    if len(event_counts) <= 10:  # Показываем только если типов не слишком много
                        ax4 = axes[1, 1]
                        
                        # Сортируем по количеству
                        sorted_events = sorted(event_counts.items(), key=lambda x: x[1], reverse=True)
                        event_names = [e[0] for e in sorted_events]
                        event_values = [e[1] for e in sorted_events]
                        
                        bars = ax4.bar(range(len(event_names)), event_values)
                        ax4.set_title('Распределение событий по типам')
                        ax4.set_xlabel('Тип события')
                        ax4.set_ylabel('Количество')
                        ax4.set_xticks(range(len(event_names)))
                        ax4.set_xticklabels(event_names, rotation=45, ha='right')
                        
                        # Добавляем значения на столбцы
                        for bar in bars:
                            height = bar.get_height()
                            ax4.text(bar.get_x() + bar.get_width()/2., height,
                                    f'{int(height)}', ha='center', va='bottom', fontsize=9)
            
            plt.tight_layout()
            plt.savefig(self.config.OUTPUT_GRAPH_PATH, dpi=150, bbox_inches='tight')
            print(f"  График сохранен в {self.config.OUTPUT_GRAPH_PATH}")
            
            # Показываем график (опционально)
            # plt.show()
            
        except Exception as e:
            print(f"  Ошибка при создании графика: {e}")
    
    def run_monitoring(self):
        """Основной метод запуска мониторинга"""
        
        print("=" * 70)
        print("АВТОМАТИЗИРОВАННЫЙ МОНИТОРИНГ И РЕАГИРОВАНИЕ НА УГРОЗЫ")
        print("=" * 70)
        
        self.start_time = time.time()
        all_threats = []
        all_responses = []
        
        # Этап 1: Сбор данных
        print("\n1. СБОР ДАННЫХ")
        print("-" * 40)
        
        # Парсинг логов Suricata
        logs = self.parse_suricata_logs()
        
        # Проверка IP через VirusTotal (если указаны в конфигурации)
        if self.config.SUSPICIOUS_IPS:
            print("\nПроверка IP-адресов через VirusTotal API...")
            for ip in self.config.SUSPICIOUS_IPS[:5]:  # Проверяем до 5 IP (ограничение API)
                result = self.check_virustotal_ip(ip)
                
                if result:
                    if result.get('status') in ['malicious', 'suspicious']:
                        threat = {
                            "type": "virustotal_malicious",
                            "ip": ip,
                            "malicious_count": result.get('malicious', 0),
                            "suspicious_count": result.get('suspicious', 0),
                            "reputation_score": result.get('reputation', 0),
                            "reason": f"IP помечен как {result['status']} в VirusTotal (зловредных: {result.get('malicious', 0)})",
                            "severity": "high" if result['status'] == 'malicious' else "medium",
                            "timestamp": datetime.now().isoformat()
                        }
                        all_threats.append(threat)
                    
                    # Соблюдаем лимит запросов к API
                    time.sleep(self.config.VIRUSTOTAL_REQUEST_DELAY)
        
        # Этап 2: Анализ данных
        print("\n2. АНАЛИЗ ДАННЫХ")
        print("-" * 40)
        
        # Анализ логов Suricata
        if logs:
            log_threats = self.analyze_logs(logs)
            all_threats.extend(log_threats)
        else:
            print("  Логи Suricata не загружены, пропускаем анализ логов")
        
        # Сканирование уязвимостей
        vuln_threats = self.scan_vulnerabilities()
        all_threats.extend(vuln_threats)
        
        # Этап 3: Реагирование на угрозы
        print("\n3. РЕАГИРОВАНИЕ НА УГРОЗЫ")
        print("-" * 40)
        
        if all_threats:
            for threat in all_threats:
                responses = self.respond_to_threat(threat)
                all_responses.extend(responses)
        else:
            print("  Угроз не обнаружено, действия не требуются")
        
        # Этап 4: Формирование отчета и визуализация
        print("\n4. ФОРМИРОВАНИЕ ОТЧЕТА И ВИЗУАЛИЗАЦИЯ")
        print("-" * 40)
        
        if all_threats or logs:
            report = self.generate_report(all_threats, all_responses)
            self.visualize_results(all_threats, logs)
            
            # Вывод сводки
            print("\n" + "=" * 70)
            print("СВОДКА АНАЛИЗА")
            print("=" * 70)
            print(f"Всего обнаружено угроз: {report['summary']['total_threats']}")
            print(f"Критических угроз: {report['summary']['critical_threats']}")
            print(f"Высокоуровневых угроз: {report['summary']['high_threats']}")
            print(f"Среднеуровневых угроз: {report['summary']['medium_threats']}")
            print(f"Низкоуровневых угроз: {report['summary']['low_threats']}")
            print(f"Предпринято действий: {report['summary']['actions_taken']}")
            print(f"Время выполнения: {report['report_metadata']['scan_duration_seconds']} секунд")
            
            # Вывод рекомендаций
            if report['recommendations']:
                print("\nРЕКОМЕНДАЦИИ:")
                for rec in report['recommendations']:
                    print(f"  [{rec['priority'].upper()}] {rec['recommendation']}")
                    
        else:
            print("Нет данных для анализа. Проверьте:")
            print("  1. Наличие файла логов Suricata")
            print("  2. Настройку API ключа VirusTotal")
            print("  3. Наличие подозрительных IP в конфигурации")
        
        print(f"\nМониторинг завершен в {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# Запуск мониторинга
if __name__ == "__main__":
    config = Config()
    
    # Проверка обязательных настроек
    if config.VIRUSTOTAL_API_KEY == "ВАШ_API_КЛЮЧ":
        print("ВНИМАНИЕ: Не установлен API ключ VirusTotal.")
        print("Для использования полного функционала получите ключ на https://www.virustotal.com/")
        print("и установите его в переменной VIRUSTOTAL_API_KEY.")
        print("Продолжаем без проверки IP через VirusTotal...\n")
    
    monitor = ThreatMonitor(config)
    monitor.run_monitoring()
