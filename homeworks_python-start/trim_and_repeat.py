def trim_and_repeat(n, m, k):
    res = n[m:]
    if k > 0:
        res2 = res + res
        return res2
    else:
        return res

stroka = str(input("Введите строку:"))
offset = 0
repeat = 1

#print(sum_distance(num1, num2))
print(trim_and_repeat(stroka, offset, repeat))
