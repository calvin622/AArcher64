
import re
import pyvex


class Gadget:
    def __init__(self, address, instructions, length, controlled_registers, constraint_solutions, return_type, sp_difference, controllable_registers):
        """
        Represents a gadget with its address, instructions, length, controlled registers, and constraints.
        """
        self.address = address
        self.instructions = list(instructions)
        self.length = length
        self.controlled_registers = list(set(controlled_registers))
        self.constraint_solutions = list(constraint_solutions)
        self.return_type = return_type
        self.sp_difference = sp_difference
        self.controllable_registers = list(controllable_registers)


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


def analyse_gadget(project, unconstrained_state, mode="fast"):
    result = process_unconstrained_state(project, unconstrained_state)
    if not result:
        return []
    addr, block_list, controlled_registers, return_type = result
    total_instructions = sum([block.instructions for block in block_list])
    sp_difference = check_sp_changed(project, unconstrained_state)
    if mode == "fast":
        return [Gadget(addr, block_list, total_instructions, controlled_registers, [], return_type, sp_difference, [])]
    constraint_states = find_constraints(project, unconstrained_state)
    solutions = [solve_constraints(state) for state in constraint_states]
    controllable_registers = check_ldr_from_block(project, unconstrained_state)
    return [Gadget(addr, block_list, total_instructions, controlled_registers, solutions, return_type, sp_difference, controllable_registers)]


def check_ldr_from_block(project, state):
    found = []
    # Get the current basic block
    block = project.factory.block(state.addr)

    for instr in block.capstone.insns:
        instr_disassembled = instr.mnemonic + " " + instr.op_str

        # Check if the disassembled instruction is one of the relevant loads from the stack
        relevant_instructions = ['ldr', 'ldp', 'ldur']
        if any(instr in instr_disassembled.lower() for instr in relevant_instructions) and '[sp' in instr_disassembled.lower():
            found.append(instr_disassembled)
    return found


def check_sp_changed(project, state):
    """
    Find constraint states from a given state and return the difference in xsp.
    """
    simgr = project.factory.simgr(state)
    current_sp = state.solver.eval(state.regs.xsp)

    simgr.step()

    # Ensure there's an active state after the step
    if not simgr.active:

        return None  # No difference since there's no new state

    # Use the first active state as the updated state
    updated_state = simgr.active[0]
    new_sp = updated_state.solver.eval(updated_state.regs.xsp)

    # Calculate the difference
    sp_difference = new_sp - current_sp

    return sp_difference


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
