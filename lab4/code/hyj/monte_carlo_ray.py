import random
import math
import time
import ray

ray.init()

@ray.remote
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
walk = []
for i in range(num):
    walk += [random_walk.remote(length)]
    

for i in walk:
    x, y = ray.get(i)
    dis += math.sqrt(x**2 + y**2)
print(dis/num)
print(time.time() - start)