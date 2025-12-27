import vt
import os
import sys
import json

# ==========================================
# НАСТРОЙКА ПЕРЕД ЗАПУСКОМ:
# 1. Установите библиотеку vt-py: pip install vt-py
# 2. Получите API-ключ на VirusTotal (бесплатный или платный)
# 3. Сохраните ключ в переменной окружения VT_API_KEY или задайте ниже
# ==========================================

def main():
    # --- Получение API-ключа ---
    # Способ 1: Из переменной окружения (рекомендуется для безопасности)
    api_key = os.getenv('VT_API_KEY')
    
    # Способ 2: Прямое указание ключа (небезопасно для production)
    # api_key = "ВАШ_API_КЛЮЧ_ЗДЕСЬ"
    
    if not api_key:
        print("Ошибка: API-ключ не найден.")
        print("Установите переменную окружения VT_API_KEY или задайте ключ в коде.")
        sys.exit(1)
    
    # --- Проверка наличия файла для сканирования ---
    file_path = "dirty_data.json"  # Путь к файлу для сканирования
    if not os.path.exists(file_path):
        print(f"Файл {file_path} не найден. Создаю тестовый файл...")
        # Создаем тестовый файл с подозрительным содержимым
        with open(file_path, "w") as f:
            f.write('{"test": "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"}')
        print(f"Тестовый файл {file_path} создан.")
    
    # --- Сканирование файла через VirusTotal API ---
    try:
        print("Подключение к VirusTotal API...")
        with vt.Client(api_key) as client:
            print(f"Отправка файла {file_path} на сканирование...")
            
            # Открываем файл и отправляем на сканирование
            with open(file_path, "rb") as f:
                analysis = client.scan_file(f, wait_for_completion=True)
            
            print("\n=== РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ ===")
            print(f"ID анализа: {analysis.id}")
            print(f"Статус: {analysis.status}")
            print(f"Статистика: {analysis.stats}")
            
            # Дополнительная информация о файле
            file_hash = analysis.hash
            print(f"Хэш файла (SHA-256): {file_hash}")
            
            # Получение полного отчета о файле
            print("\n=== ПОЛНЫЙ ОТЧЕТ ===")
            file_report = client.get_object(f"/files/{file_hash}")
            
            # Выводим только основные поля из отчета
            report_data = {
                "md5": file_report.md5,
                "sha1": file_report.sha1,
                "sha256": file_report.sha256,
                "size": file_report.size,
                "last_analysis_stats": file_report.last_analysis_stats,
                "meaningful_name": file_report.meaningful_name,
                "type_tag": file_report.type_tag,
                "tags": file_report.tags,
                "times_submitted": file_report.times_submitted
            }
            
            # Красивый вывод JSON
            print(json.dumps(report_data, indent=2, ensure_ascii=False))
            
            # Интерпретация результатов
            print("\n=== ИНТЕРПРЕТАЦИЯ ===")
            stats = file_report.last_analysis_stats
            print(f"Антивирусных движков, нашедших угрозу: {stats.get('malicious', 0)}")
            print(f"Безопасных вердиктов: {stats.get('undetected', 0)}")
            
            if stats.get('malicious', 0) > 0:
                print("⚠️  ВНИМАНИЕ: Файл помечен как опасный!")
            else:
                print("✅ Файл не содержит известных угроз.")
                
    except vt.APIError as e:
        print(f"Ошибка VirusTotal API: {e}")
        if "Quota exceeded" in str(e):
            print("Превышена квота запросов. Используйте другой API-ключ или подождите.")
    except FileNotFoundError as e:
        print(f"Ошибка файла: {e}")
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")

if __name__ == "__main__":
    # ==========================================
    # КАК ЗАПУСТИТЬ:
    # 1. Установите зависимости: pip install vt-py
    # 2. Экспортируйте API-ключ: 
    #    Linux/Mac: export VT_API_KEY="ваш_ключ"
    #    Windows: set VT_API_KEY="ваш_ключ"
    # 3. Поместите файл для сканирования в ту же папку
    #    или измените переменную file_path
    # 4. Запустите: python vt_scanner.py
    # ==========================================
    main()
