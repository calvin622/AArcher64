import angr


class Gadget:
    def __init__(self, address, instructions, length, controlled_registers, constraint_solutions):
        """
        Represents a gadget with its address, instructions, length, and controlled registers.
        """
        self.address = address
        self.instructions = list(instructions)
        self.length = length
        self.controlled_registers = controlled_registers
        self.constraint_solutions = list(constraint_solutions)


def analyse_controlled_registers(project, state, address):
    """
    Take a step forward in the simulation to reach the specified address.
    """
    simgr = project.factory.simgr(state)
    sp_before = state.regs.sp
    changed_registers = []

    simgr.step()

    final_state = simgr.active[0] if simgr.active else None
    if final_state:
        # Check for changed registers (this is slow)
        changed_registers = get_changed_registers(final_state, state)

        # Check if the sp register has changed
        if state.solver.eval(final_state.regs.sp) != state.solver.eval(sp_before):
            changed_registers.append('sp')

    return changed_registers


def get_changed_registers(final_state, state):
    """
    Check for changed registers between final_state and state.
    """
    return [
        reg_name
        for reg_name in [f'x{i}' for i in range(31)]
        if state.solver.eval(final_state.regs.get(reg_name)) != state.solver.eval(state.regs.get(reg_name))
    ]


def process_unconstrained_state(project, unconstrained_state):
    """
    Process an unconstrained state and extract gadgets from it.
    """
    instruction_addr = unconstrained_state.regs.ip
    addr = unconstrained_state.solver.eval(instruction_addr)
    controlled_registers = analyse_controlled_registers(
        project, unconstrained_state.copy(), instruction_addr)

    constraint_solutions = []
    block_list = [create_block(project, addr)]

    num_ins = block_list[0].instructions

    if num_ins > 0:
        constraints = find_constraints(
            project, unconstrained_state.copy())
        for constraint in constraints:
            address = unconstrained_state.solver.eval(constraint.regs.ip)
            block_list.append(create_block(project, address))
            constraint_solutions.append(solve_constraints(constraint))
            controlled_registers.extend(analyse_controlled_registers(project, constraint, constraint.regs.ip))
        gadget = Gadget(hex(addr), block_list, num_ins, controlled_registers, constraint_solutions)
        return [gadget]

    return []


def find_constraints(project, state):
    """
    Find constraint states from a given state.
    """
    simgr = project.factory.simgr(state)
    constraint_states = []
    simgr.step()
    if len(simgr.active) >= 2:
        constraint_states.extend(simgr.active)
    return constraint_states


def solve_constraints(state):
    """
    Solve constraints and return the solution.
    """
    input_data = state.posix.stdin.load(0, state.posix.stdin.size)
    solution = state.solver.eval(input_data, cast_to=bytes)
    return solution


def create_block(project, addr):
    """
    Create a block for the specified address in the project.
    """
    block = project.factory.block(addr=addr)
    return block
