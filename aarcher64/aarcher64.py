from gadget_finder import GadgetExtractor  # Adjusted import to reflect previous code change

from config_utils import load_config

class GadgetSearcher:
    def __init__(self):
        self.extractor = None
        self.simgr = None
        self.config = load_config()

    def initialize_project_simgr(self):
        binary_path = input("Enter the path to the binary: ")
        self.extractor = GadgetExtractor(GadgetExtractor.initialize_project(binary_path))
        self.simgr = self.extractor.create_simgr(self.extractor.project)

    def search_gadgets(self, mode):
        gadgets = self.extractor.extract_gadgets(self.simgr, mode)
        self.extractor.print_gadgets(gadgets)

    def get_mode(self):
        mode = self.config.enable_contraint_finding
        return mode

    @staticmethod
    def print_menu():
        print("Menu:")
        print("1. Search Binary")
        print("2. Quit")

    @staticmethod
    def get_user_choice():
        valid_choices = {1, 2}
       
        
        while True:
            try:
                choice = int(input("Enter your choice (1-2): ").strip())
            except ValueError:
                print("Invalid choice. Please enter a number.")
                continue  # Skip the rest of the loop and ask for the choice again
            
            if choice not in valid_choices:
                print("Invalid choice. Please try again.")
                continue  # Skip the rest of the loop and ask for the choice again

            if choice in valid_choices:
                return choice
            
            if choice == 2:
                return 0, choice
            
            else:
                print("Invalid instruction count. Please try again.")


if __name__ == "__main__":
    searcher = GadgetSearcher()
    while True:
        searcher.print_menu()
        choice = searcher.get_user_choice()  # Assuming get_user_choice now returns ints
        if choice in {1}:
            searcher.initialize_project_simgr()
            mode = searcher.get_mode()
            searcher.search_gadgets(mode)
        elif choice == 2:
            print("Exiting...")
            break

