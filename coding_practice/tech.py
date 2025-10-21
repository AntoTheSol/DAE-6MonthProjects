li = [5,1,4,3,5,2,4]

def repeat(self):
    
    num = 0
    for num in range(len(li)):

        re = li[num]

        if re == li[num+1]:

            re = li[num+1]
            
            print(int(re))
        

repeat(li)
        
