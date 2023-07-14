
import re

class Gadget:
    def __init__(self, address, instructions, length, controlled_registers, constraint_solutions):
        """
        Represents a gadget with its address, instructions, length, controlled registers, and constraints.
        """
        self.address = address
        self.instructions = list(instructions)
        self.length = length
        self.controlled_registers = controlled_registers
        self.constraint_solutions = list(constraint_solutions)


def analyse_controlled_registers(block):
    """
    Take a step forward in the simulation to reach the specified address.
    """
    registers = []
    pattern = r"PUT\(([^)]+)\)"
    matches = re.findall(pattern, str(block.vex))

    for match in matches:
        if match.startswith("x") or match.startswith("v"):
            registers.append(match)

    return registers
    
def process_unconstrained_state(project, unconstrained_state):
    """
    Process an unconstrained state and extract gadgets from it.
    """
    instruction_addr = unconstrained_state.regs.ip
    addr = unconstrained_state.solver.eval(instruction_addr)
    
    constraint_solutions = []
    block_list = [create_block(project, addr)]

    controlled_registers = analyse_controlled_registers(block_list[0])

    num_ins = block_list[0].instructions

    if num_ins > 0:
        constraints = find_constraints(
            project, unconstrained_state.copy())
        for constraint in constraints:
            address = unconstrained_state.solver.eval(constraint.regs.ip)
            block = create_block(project, address)
            block_list.append(block)
            constraint_solutions.append(solve_constraints(constraint))
            controlled_registers.extend(analyse_controlled_registers(block))
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
