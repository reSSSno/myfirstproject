# Создаем словарь с данными о покупках из purchase_log.txt

i = 0
purchases = {}
with open('/content/sample_data/purchase_log.txt') as f:
  next(f)
  for line in f:
    slovar = json.loads(line)
    #print(slovar.get('user_id')+" "+slovar.get('category'))
    key1 = slovar.get('user_id')
    key2 = slovar.get('category')
    purchases[key1] = key2
    i += 1

# Обрабатываем visit_log.csv построчно и записываем результат
with open('/content/sample_data/visit_log.csv', 'r', encoding='utf-8') as visit_file, \
     open('/content/sample_data/funnel.csv', 'w', encoding='utf-8') as funnel_file:
    
    # Записываем заголовок
    header = visit_file.readline().strip()
    funnel_file.write(header + ',category\n')
    
    # Обрабатываем каждую строку visit_log.csv
    for line in visit_file:
        line = line.strip()
        if line:
            user_id, source = line.split(',')

            # Проверяем, есть ли покупка у этого пользователя
            if user_id == user_id in purchases:
                category = purchases[user_id]
                funnel_file.write(f'{line},{category}\n')

#Проверка

f = open('/content/sample_data/funnel.csv', 'r')

f.readlines()
