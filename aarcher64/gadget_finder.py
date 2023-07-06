import angr
import claripy
# Import the function from the separate file
from analyse_gadgets import process_unconstrained_state


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


def extract_gadgets(project, simgr):
    """
    Extract gadgets from the given project and simulation manager.
    """
    gadgets = []

    while simgr.active:

        simgr.step()

        for state in simgr.active:

            gadgets.extend(process_unconstrained_state(project, state))

    return gadgets


def print_gadgets(gadgets):
    """
    Print information about the extracted gadgets.
    """
    if gadgets:
        print("Gadget Information:")
        for i, gadget in enumerate(gadgets):
            print(f"--- Gadget {i + 1} {gadget.address} ---")
            print(f"Number of instructions: {gadget.length}")
            print(f"Controlled registers: {gadget.controlled_registers}")
            print(f"Constraint solutions: {gadget.constraint_solutions}")
            print(gadget.instructions())
    else:
        print("No gadgets found.")


def execute_binary(binary_path):
    try:
        project = angr.Project(binary_path, auto_load_libs=False)

        state = project.factory.entry_state(stdin=angr.SimFile)
        return_address = claripy.BVS("return_address", project.arch.bits)
        frame_pointer = claripy.BVS("frame_pointer", project.arch.bits)
        state = set_registers_symbolic(
            state, return_address, frame_pointer, project)

        simgr = project.factory.simgr(state)

        gadgets = extract_gadgets(project, simgr)

        print_gadgets(gadgets)
    except Exception as e:
        print("An error occurred:", e)


if __name__ == "__main__":
    binary_path = "/home/ubuntu/AArcher64/binaries/bof642"
    execute_binary(binary_path)
