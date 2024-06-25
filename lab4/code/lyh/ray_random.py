import random
#import math
import time
import ray
const_n=1_0000
const_step=10_0000
const_task_num=4
const_part_num=4
@ray.remote
class times_of_random_walk:
    def __init__(self,step,k,parts):
        self.step=step
        self.k=k
        self.parts=parts
    def random_walk(self):
        m=self.step//self.parts
        x=0
        y=0
        id_list=[]
        for i in range(self.parts):
            id_list.append(part_of_random_walk.remote(m))
        for i in range(0,len(id_list)):
            (dx, dy)=ray.get(id_list[i])
            x += dx
            y += dy
        return (x, y)
    def run_k_times(self):
        x=0
        y=0
        for i in range(self.k):
            walk = self.random_walk()
            x+=walk[0]
            y+=walk[1]
        return (x,y)
@ray.remote
def part_of_random_walk(m):
    x=0
    y=0
    for i in range(m):
        (dx, dy) = random.choice([(0, 1), (0, -1), (1, 0), (-1, 0)])
        x += dx
        y += dy
    return (x, y)

ray.init()
start_time=time.time()
n=const_n
k=n//const_task_num
id_list=[]
for i in range(const_task_num):
    t=times_of_random_walk.remote(const_step,k,const_part_num)
    id_list.append(t.run_k_times.remote())
x=0
y=0
for i in range(0,len(id_list)):
    walk=ray.get(id_list[i])
    x+=walk[0]
    y+=walk[1]
print(x/n,y/n,time.time()-start_time)