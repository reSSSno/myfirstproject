import json

i = 0
purchases = {}
with open('/content/sample_data/purchase_log.txt') as f:
  next(f) #Пропускаем заголовок
  for line in f:
    slovar = json.loads(line)
    #print(slovar.get('user_id')+" "+slovar.get('category'))
    key1 = slovar.get('user_id')
    key2 = slovar.get('category')
    purchases[key1] = key2
    i += 1
 
#del(purchases['user_id'])
#print(purchases)

#Проверка
n = 0
for key, value in purchases.items():
  print(key, value)
  n += 1
  if n > 1:
    break


#Проверить можно в google colab
