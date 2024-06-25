import random
import math
import time



def random_walk(n):
    x, y = 0, 0
    for i in range(n):
        (dx, dy) = random.choice([(0, 1), (0, -1), (1, 0), (-1, 0)])
        x += dx
        y += dy
    return (x, y)

# 测试随机游走函数
start = time.time()
dis = 0
num = 10000
length = 10000
for i in range(num):
    walk = random_walk(length)
    dis += math.sqrt(walk[0]**2 + walk[1]**2)
    

print(dis/num)
print(time.time() - start)