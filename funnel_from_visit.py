# Создаем словарь с данными о покупках из purchase_log.txt
purchases = {}

with open('/content/sample_data/purchase_log.txt', 'r', encoding='utf-8') as f:
    next(f)  # пропускаем заголовок
    for line in f:
        line = line.strip()
        if line:
            user_id, category = line.split('", "')
            user_id = user_id.replace('"', '')
            category = category.replace('"', '')
            purchases[user_id] = category

# Обрабатываем visit_log.csv построчно и записываем результат
with open('/content/sample_data/visit_log.csv', 'r', encoding='utf-8') as visit_file:
  with open('/content/sample_data/funnel.csv', 'w', encoding='utf-8') as funnel_file:
    
    # Записываем заголовок
    header = visit_file.readline().strip()
    funnel_file.write(header + ',category\n')
    
    # Обрабатываем каждую строку visit_log.csv
    for line in visit_file:
        line = line.strip()
        if line:
            user_id, source = line.split(',')
            
            # Проверяем, есть ли покупка у этого пользователя
            if user_id in purchases:
                category = purchases[user_id]
                funnel_file.write(f'{line},{category}\n')


#Проверка

f = open('/content/sample_data/funnel.csv', 'r')

f.readlines()
