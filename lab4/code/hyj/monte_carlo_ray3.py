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


const_task_part = 10
const_walk_part = 10

@ray.remote
def main(num, length):
    walk = []
    for i in range(num):
        part_walk = []
        for i in range (const_walk_part):
            part_walk += [random_walk.remote(length//const_walk_part)]
        walk += [part_walk]
    return walk




# 测试随机游走函数
start = time.time()
dis = 0
num = 10000
length = 1000000

walk = []
for i in range(const_task_part):
    part_walk = main.remote(num//const_task_part, length)
    walk += [part_walk]

# print(walk)


for i in walk:
    part_walk = ray.get(i)
    # print(part_walk)
    for j in part_walk:
        fact_x = 0
        fact_y = 0
        for k in j:
            x, y = ray.get(k)
            fact_x += x
            fact_y += y
        dis += math.sqrt(fact_x**2 + fact_y**2)
print(dis/num)
print(time.time() - start)