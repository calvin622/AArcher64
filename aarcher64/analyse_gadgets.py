
import re, pyvex


class Gadget:
    def __init__(self, address, instructions, length, controlled_registers, constraint_solutions, return_type):
        """
        Represents a gadget with its address, instructions, length, controlled registers, and constraints.
        """
        self.address = address
        self.instructions = list(instructions)
        self.length = length
        self.controlled_registers = list(set(controlled_registers))
        self.constraint_solutions = list(constraint_solutions)
        self.return_type = return_type


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

def analyse_return_type(block):
    """
    Find return type.
    """
    irsb = block.vex
    return_type = irsb.jumpkind
    
    return return_type


def process_unconstrained_state(project, unconstrained_state):
    instruction_addr = unconstrained_state.regs.ip
    addr = unconstrained_state.solver.eval(instruction_addr)

    block_list = [create_block(project, addr)]

    if block_list and block_list[0].instructions > 1:
        controlled_registers = analyse_controlled_registers(block_list[0])
        return_type = analyse_return_type(block_list[0])
        return addr, block_list, controlled_registers, return_type

    return None


def analyse_gadget_fast(project, unconstrained_state):
    result = process_unconstrained_state(project, unconstrained_state)
    if result:
        addr, block_list, controlled_registers, return_type = result
        total_instructions = sum(blocks.instructions for blocks in block_list)
        if total_instructions > 1 and 'xsp' in controlled_registers:
            return [Gadget(hex(addr), block_list, total_instructions, controlled_registers, return_type, [])]

    return []


def analyse_gadget_slow(project, unconstrained_state):
    result = process_unconstrained_state(project, unconstrained_state)

    if result:
        addr, block_list, controlled_registers, return_type = result
        constraint_solutions = []

        constraints = find_constraints(project, unconstrained_state.copy())

        for constraint in constraints:
            address = unconstrained_state.solver.eval(constraint.regs.ip)
            block = create_block(project, address)
            block_list.append(block)

            constraint_solutions.append(solve_constraints(constraint))
            controlled_registers.extend(analyse_controlled_registers(block))
        total_instructions = sum(blocks.instructions for blocks in block_list)
        if total_instructions > 1 and 'xsp' in controlled_registers:
            return [
                Gadget(hex(addr), block_list, total_instructions,
                        controlled_registers, constraint_solutions, return_type)
            ]

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
