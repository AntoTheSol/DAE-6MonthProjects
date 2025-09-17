print("This is my program")

first_name = input("Please enter your first name: ")
last_name = input("Please enter your last name: ")
current_age = int(input("Please enter your age: "))

print("Hello " + first_name + " " + last_name + ", you are " + str(current_age) + ".")

if current_age <= 0:
    print("Please input an appropriate age")
    current_age = int(input("Please enter your age: "))
    
elif current_age <= 17: 
    print("Must be 18 or older to signup.")
    
else:
    
    print("You are elligible to sign up, enter information below.")
    signup_email = input("Enter your email: ")
    user_name = input("Create a user name: ")
    pass_word = input("Create a password: ")

    ShowInfo = input("Would you like to display your information? (yes/no): ")

    if ShowInfo == "yes":

        print(" ")
        print("Your information: ")
        print("Email: " + (signup_email))
        print("Username: " + (user_name))
        print("Password sent to email.")
        print("First Name: " + (first_name))
        print("Last Name: " + (last_name))
        print("Age: " + str(current_age))

    elif ShowInfo == "no":

        delete = input("Would you like to delete your account? (yes/no):")

        if delete == "yes":

            signup_email = "n/a"
            user_name = "n/a"
            pass_word = "n/a"
            first_name = "n/a"
            last_name = "n/a"
            age = "n/a"
            current_age = "n/a"

            print(" ")
            print("Your information: ")
            print("Email: " + (signup_email))
            print("Username: " + (user_name))
            print("Password: " + (pass_word))
            print("First Name: " + (first_name))
            print("Last Name: " + (last_name))
            print("Age: " + str(current_age))

        elif delete == "no":
            print("Thank you for staying with us.")

        else:
            print("Please enter 'yes' or 'no'.")

    
