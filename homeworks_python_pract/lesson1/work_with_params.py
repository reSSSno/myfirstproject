import requests

def get_weather():
    # API ключ (бесплатный, нужно зарегистрироваться на openweathermap.org)
    API_KEY = "ваш_api_ключ_здесь"
    BASE_URL = "http://api.openweathermap.org/data/2.5/weather"
    
    # Получение названия города от пользователя
    city = input("Введите название города: ").strip()
    
    if not city:
        print("Ошибка: название города не может быть пустым!")
        return
    
    # Параметры запроса
    params = {
        'q': city,
        'appid': API_KEY,
        'units': 'metric',  # для получения температуры в Celsius
        'lang': 'ru'        # для получения описания на русском
    }
    
    try:
        # Отправка GET-запроса
        response = requests.get(BASE_URL, params=params)
        
        # Проверка статуса ответа
        if response.status_code == 200:
            # Преобразование ответа в JSON
            weather_data = response.json()
            
            # Извлечение данных о погоде
            temperature = weather_data['main']['temp']
            description = weather_data['weather'][0]['description']
            city_name = weather_data['name']
            country = weather_data['sys']['country']
            
            # Вывод результатов
            print("\n" + "=" * 40)
            print(f"Погода в городе {city_name}, {country}:")
            print(f"Температура: {temperature}°C")
            print(f"Описание: {description.capitalize()}")
            print("=" * 40)
            
        elif response.status_code == 404:
            print(f"Ошибка: Город '{city}' не найден!")
        else:
            print(f"Ошибка API: {response.status_code}")
            print(f"Сообщение: {response.json().get('message', 'Неизвестная ошибка')}")
            
    except requests.exceptions.RequestException as e:
        print(f"Ошибка соединения: {e}")
    except KeyError as e:
        print(f"Ошибка обработки данных: неверный формат ответа")
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")

# Запуск программы
if __name__ == "__main__":
    get_weather()
