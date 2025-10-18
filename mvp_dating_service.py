boys = ["Peter", "Alex", "John", "Arthur", "Richard"] 
res = sorted(boys)
girls = ["Kate", "Liza", "Kira", "Emma", "Trisha"] 
res2 = sorted(girls)

i = 0
perfect_para = []
print("#"*15,"\n","Идеальная пара:")
for n1, n2 in zip(res, res2):
    print(n1 + " and " + n2)
print("#"*15,"\n")

boys = ["Peter", "Alex", "John", "Arthur", "Richard", "Michael"] 
res = sorted(boys)
girls = ["Kate", "Liza", "Kira", "Emma", "Trisha"] 
res2 = sorted(girls)
print(res)
print(res2)
