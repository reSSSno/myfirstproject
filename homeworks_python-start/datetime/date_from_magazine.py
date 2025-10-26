from datetime import datetime

def parse_newspaper_dates():
    # The Moscow Times - Wednesday, October 2, 2002
    moscow_times_str = "Wednesday, October 2, 2002"
    moscow_times_date = datetime.strptime(moscow_times_str, "%A, %B %d, %Y")
    
    # The Guardian - Friday, 11.10.13
    guardian_str = "Friday, 11.10.13"
    guardian_date = datetime.strptime(guardian_str, "%A, %d.%m.%y")
    
    # Daily News - Thursday, 18 August 1977
    daily_news_str = "Thursday, 18 August 1977"
    daily_news_date = datetime.strptime(daily_news_str, "%A, %d %B %Y")
    
    # Вывод результатов
    print("The Moscow Times:")
    print(f"Исходная строка: {moscow_times_str}")
    print(f"Объект datetime: {moscow_times_date}")
    print(f"Формат: %A, %B %d, %Y")
    print()
    
    print("The Guardian:")
    print(f"Исходная строка: {guardian_str}")
    print(f"Объект datetime: {guardian_date}")
    print(f"Формат: %A, %d.%m.%y")
    print()
    
    print("Daily News:")
    print(f"Исходная строка: {daily_news_str}")
    print(f"Объект datetime: {daily_news_date}")
    print(f"Формат: %A, %d %B %Y")
    print()

# Альтернативная функция с возвратом словаря
def get_newspaper_date_formats():
    formats = {
        "The Moscow Times": "%A, %B %d, %Y",
        "The Guardian": "%A, %d.%m.%y", 
        "Daily News": "%A, %d %B %Y"
    }
    return formats

# Пример использования
if __name__ == "__main__":
    parse_newspaper_dates()
    
    # Демонстрация с использованием словаря форматов
    print("Форматы дат для каждой газеты:")
    formats = get_newspaper_date_formats()
    
    test_dates = {
        "The Moscow Times": "Wednesday, October 2, 2002",
        "The Guardian": "Friday, 11.10.13",
        "Daily News": "Thursday, 18 August 1977"
    }
    
    for newspaper, date_str in test_dates.items():
        format_str = formats[newspaper]
        parsed_date = datetime.strptime(date_str, format_str)
        print(f"{newspaper}: {format_str} -> {parsed_date}")
