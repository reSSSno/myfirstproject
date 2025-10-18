def sum_distance(num1, num2):
    numbers = list(range(num1, num2+1))
    #print (numbers)
    res = sum(numbers)
    return res

num1 = int(input("Введите 1 число:"))
num2 = int(input("Введите 2 число:"))

print(sum_distance(num1, num2))
