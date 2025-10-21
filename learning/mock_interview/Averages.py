"""

def calculate_average(scores): 
    total = 0 
    for score in scores: 
        total = total + score   # bug: should accumulate, not overwrite 
    average = total / len(scores) 
    print("Average:", average) 
 
calculate_average([80, 90, 100, 100])

"""

#Find the 2nd largest number in list of numbers without using sorted

""""""
def second_largest(numbers):

    for i in range(len(numbers)):

        for j in range(i + 1, len(numbers)):
            if numbers[i] > numbers[j]:

                temp = numbers[i]
                numbers[i] = numbers[j]
                numbers[j] = temp

    second_largest = numbers[-2]
    print(numbers[-2])


second_largest([1,2,3])

""""""

def print_even_or_odd(numbers):
    for n in numbers:
        if n % 2 == 0:  # syntax bug
            print(n, "is even")
        else:
            print(n, "is odd")
print_even_or_odd([1, 2, 3])


4. Create a function which will print the reverse of a string.

