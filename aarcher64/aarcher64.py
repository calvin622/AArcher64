from gadget_finder import create_simgr, initialise_project, extract_gadgets, print_gadgets


def initialize_project_simgr():
    # Get the path to the binary from the user
    binary_path = input("Enter the path to the binary: ")

    # Initialize the project with the provided binary path
    project = initialise_project(binary_path)

    # Create a simulation manager for the project
    simgr = create_simgr(project)

    return project, simgr


def search_gadgets(project, simgr, mode):
    gadgets = extract_gadgets(project, simgr, mode)
    print_gadgets(gadgets)


def print_menu():
    # Display the menu options
    print("Menu:")
    print("1. Fast search (no constraint solving)")
    print("2. Slow search (constraint solving)")
    print("3. Quit")


def get_user_choice():
    while True:
        # Get user input for the menu choice
        choice = input("Enter your choice (1-3): ")
        if choice in ["1", "2", "3"]:
            return choice
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    while True:
        # Display the menu
        print_menu()
        choice = get_user_choice()
        if choice in ["1", "2"]:
            project, simgr = initialize_project_simgr()
            mode = "fast" if choice == "1" else "slow"
            search_gadgets(project, simgr, mode)
        elif choice == "3":
            print("Exiting...")
            break
