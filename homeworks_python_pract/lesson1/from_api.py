import requests

def get_posts():
    # URL публичного API JSONPlaceholder
    url = "https://jsonplaceholder.typicode.com/posts"
    
    try:
        # Отправка GET-запроса
        response = requests.get(url)
        
        # Проверка статуса ответа
        if response.status_code == 200:
            # Преобразование ответа в JSON
            posts = response.json()
            
            print("Первые 5 постов из JSONPlaceholder API:\n")
            print("=" * 50)
            
            # Извлечение и вывод первых 5 постов
            for i, post in enumerate(posts[:5], 1):
                print(f"Пост #{i}")
                print(f"Заголовок: {post['title']}")
                print(f"Текст: {post['body']}")
                print("-" * 50)
                
        else:
            print(f"Ошибка при запросе: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print(f"Ошибка соединения: {e}")

# Запуск функции
if __name__ == "__main__":
    get_posts()
