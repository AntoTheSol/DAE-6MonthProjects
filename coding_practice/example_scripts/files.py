

def main():
    with open( "fruits.txts", "w" ) as file:
        file.write("apple\n")
        file.write("banana\n")
        file.write("cherry\n")
        file.write("cherry\n")
        file.write("cherry\n")

# open will create a file if it doesn't exist and the mode can be write, open, or read using a variable called file.

    with open( "fruits.txts", "r" ) as readFile:
        for currentLine in readFile:
            print(currentLine.rstrip( " \n " ))

    with open( "fruits.txts", "r" ) as readFile:
        contents = readFile.read()
        print(contents)

main()