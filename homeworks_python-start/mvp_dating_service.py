boys = ["Peter", "Alex", "John", "Arthur", "Richard"] 
res = sorted(boys)
girls = ["Kate", "Liza", "Kira", "Emma", "Trisha"] 
res2 = sorted(girls)


print("#"*15,"\n","Идеальная пара:")
for n1, n2 in zip(res, res2):
    print(n1 + " and " + n2)
print("#"*15,"\n")

boys = ["Peter", "Alex", "John", "Arthur", "Richard", "Michael"] 
res3 = sorted(boys)
girls = ["Kate", "Liza", "Kira", "Emma", "Trisha"] 
res4 = sorted(girls)

if len(res3) > len(res4):
    print("Внимание, кто-то может остаться без пары!")
elif len(res4) > len(res3):
    print("Внимание, кто-то может остаться без пары!")
else:
    print("#"*15,"\n","Идеальная пара:")
    for n1, n2 in zip(res3, res4):
        print(n1 + " and " + n2)
    print("#"*15,"\n")
