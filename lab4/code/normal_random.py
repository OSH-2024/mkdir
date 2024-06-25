import random
#import math
import time
const_n=10000
const_step=100000
def random_walk(n):
    x, y = 0, 0
    for i in range(n):
        (dx, dy) = random.choice([(0, 1), (0, -1), (1, 0), (-1, 0)])
        x += dx
        y += dy
    return (x, y)

start_time=time.time()
#distance=0
n=const_n
step=const_step
x=0
y=0
for i in range(n):
    walk = random_walk(step)
    x+=walk[0]
    y+=walk[1]
    #distance=distance+math.sqrt(walk[0]**2+walk[1]**2)
print(x/n,y/n,time.time()-start_time)