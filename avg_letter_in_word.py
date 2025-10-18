word = "asdasdasdasdas"
n = len(word)
middle = n // 2

if n % 2 == 0:
    print(word[middle-1:middle+1])
else:
    print(word[middle])
