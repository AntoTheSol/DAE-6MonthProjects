# Exception or try catching is best used for error handling


def main():

    uName = input("Type in your name: ")
    print(uName)

    try:
        uAge = int(input("Type in your age: "))
        print(uAge)
        
    except ValueError as myValueError:
        print("Error has occured. Number's only.", myValueError ) 

    except ZeroDivisionError as myZeroDivisionErrorss:
        print("Error has occured. Number's only.", myValueError )

    except:
        print("Error has occured.")
    else:
        print( "Program was successful." )
    finally:
        print( "End of Program." )


main()