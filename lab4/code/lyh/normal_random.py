import random
import time
const_n=1_0000 #随机游走次数
const_step=10_0000 #每次随机游走步数
def random_walk(n):
    x, y = 0, 0
    for i in range(n):
        (dx, dy) = random.choice([(0, 1), (0, -1), (1, 0), (-1, 0)])
        x += dx
        y += dy
    return (x, y)

start_time=time.time()
n=const_n
step=const_step
x=0
y=0
for i in range(n):
    walk = random_walk(step)
    x+=walk[0]
    y+=walk[1]
print(x/n,y/n,time.time()-start_time)