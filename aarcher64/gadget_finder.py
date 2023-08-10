import angr
import claripy
# Import the function from the separate file
from analyse_gadgets import analyse_gadget_fast, analyse_gadget_slow


def set_registers_symbolic(state, return_address, frame_pointer, project):
    """
    Set registers x0 to x30 in the state to symbolic variables.
    """
    state.regs.sp = state.solver.BVS('sp_symbolic', state.arch.bits)

    register_names = ['x{}'.format(i) for i in range(31)]
    for reg_name in register_names:
        symbolic_var = state.solver.BVS(
            f'{reg_name}_symbolic', state.arch.bits)
        setattr(state.regs, reg_name, symbolic_var)

    return state


def extract_gadgets(project, simgr, menu_option):
    gadgets = []
    gadgets_analysed = 0

    while simgr.active:
        simgr.step()
        for state in simgr.active:
            addr = state.solver.eval(state.regs.ip)

            if not any(addr in block.instruction_addrs for gadget in gadgets for block in gadget.instructions):
                if menu_option == "fast":
                    gadgets.extend(analyse_gadget_fast(project, state))
                elif menu_option == "slow":
                    gadgets.extend(analyse_gadget_slow(project, state))
                else:
                    raise ValueError("Invalid menu option")
                
                gadgets_analysed += 1
                print(f"gadgets analysed: {gadgets_analysed}", end="\r")

    return gadgets



def print_gadgets(gadgets):
    """
    Print information about the extracted gadgets.
    """
    if gadgets:
        print("Gadget Information:")
        for i, gadget in enumerate(gadgets, start=1):
            print(f"--- Gadget {i} {gadget.address} ---")
            print(f"Number of instructions: {gadget.length}")
            print(f"Controlled registers: {gadget.controlled_registers}")
            for num, solution in enumerate(gadget.constraint_solutions, start=1):
                print(f"Constraint solution {num}: {solution}")
            print(f"Type of Return: {gadget.return_type}")

            sorted_blocks = sorted(gadget.instructions,
                                   key=lambda block: block.addr)
            for index, block in enumerate(sorted_blocks, start=1):
                if index > 1:
                    print(f"Constraint {index}")
                instructions = block.pp()

    else:
        print("No gadgets found.")


def create_simgr(project):
    try:

        state = project.factory.entry_state(stdin=angr.SimFile)
        return_address = claripy.BVS("return_address", project.arch.bits)
        frame_pointer = claripy.BVS("frame_pointer", project.arch.bits)
        #state = set_registers_symbolic(state, return_address, frame_pointer, project)

        simgr = project.factory.simgr(state)
        # gadgets = extract_gadgets(project, simgr)
        return simgr

        # print_gadgets(gadgets)
    except Exception as e:
        print("An error occurred:", e)


def initialise_project(binary_path):
    try:
        project = angr.Project(binary_path, auto_load_libs=False)
        return project
    except Exception as e:
        print("An error occurred:", e)
