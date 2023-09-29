import angr

from analyse_gadgets import GadgetAnalyzer
from config_utils import load_config



class GadgetExtractor:
    def __init__(self, project):
        self.project = project
        self.gadget_analyzer = GadgetAnalyzer(project)
        self.config = load_config()

    def set_registers_symbolic(self, state):
       
        state.options.add(angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        return state

    def extract_gadgets(self, simgr, mode):
        gadgets = []
        gadgets_analyzed = 0
        while simgr.active and gadgets_analyzed < self.config.gadget_search_amount:
            simgr.step()
            for state in simgr.active:
            
                addr = state.solver.eval(state.regs.ip)
                if not any(addr in block.instruction_addrs for gadget in gadgets for block in gadget.instructions):
                    state = self.set_registers_symbolic(state)
                    gadgets.extend(self.gadget_analyzer.analyze(state, mode))
                    gadgets_analyzed += 1
                    print(f"gadgets analyzed: {gadgets_analyzed} | gadgets found: {len(gadgets)}", end="\r")
                 
        return gadgets

    def print_gadgets(self, gadgets):
        if gadgets:
            print(f"\n", end="\r")
            for i, gadget in enumerate(gadgets, start=1):
                print(f"{'*' * 60}")
                print(f"{'Gadget Number:':<25} {i} | {gadget.address:<25}")
                print(f"{'Number of instructions:':<25} {gadget.length:<25}")
                print(
                    f"{'Controllable registers:':<25} {', '.join(gadget.controllable_registers):<25}")
                print(f"{'sp difference:':<25} {hex(gadget.sp_difference):<25}")
                print(f"{'Type of Return:':<25} {gadget.return_type:<25}")
                print(
                    f"{'Return Controllable:':<25} {', '.join(gadget.return_controllable):<25}")
                for num, solution in enumerate(gadget.constraint_solutions, start=1):
                    print(
                        f"{'Gadget':<25} {i}.{num} condition: {gadget.constraint_register} = {solution:<25}")
                print(f"{'-' * 60}")

                sorted_blocks = sorted(gadget.instructions,
                                       key=lambda block: block.addr)
                for index, block in enumerate(sorted_blocks, start=1):
                    if index > 1:
                        print(f"{'-' * 60}")
                        print(f"{'Gadget:':<25} {i}.{index - 1:<25}")
                    instructions = block.pp()  # Assuming pp() prints the instructions
                print(f"{'*' * 60}")
                print("\n")
        else:
            print("No gadgets found.")

    @staticmethod
    def create_simgr(project):
        try:
            state = project.factory.entry_state(stdin=angr.SimFile)
            simgr = project.factory.simgr(state)
            return simgr
        except Exception as e:
            print(f"Error in create_simgr: {e}")
            return None

    @staticmethod
    def initialize_project(binary_path):
        try:
            project = angr.Project(binary_path, auto_load_libs=False)
            return project
        except Exception as e:
            print(f"Error in initialize_project: {e}")
            return None
