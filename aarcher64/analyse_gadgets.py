class Gadget:
    def __init__(self, address, instructions, length, controlled_registers):
        """
        Represents a gadget with its address, instructions, length, and controlled registers.
        """
        self.address = address
        self.instructions = instructions
        self.length = length
        self.controlled_registers = controlled_registers
        
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
    
         # Check for changed registers **this is slow**
        changed_registers = [
            reg_name
            for reg_name in [f'x{i}' for i in range(31)]
            if state.solver.eval(final_state.regs.get(reg_name)) != state.solver.eval(state.regs.get(reg_name))
        ]

        # Check if the sp register has changed
        if state.solver.eval(final_state.regs.sp) != state.solver.eval(sp_before):
            changed_registers.append('sp')

    return changed_registers

def process_unconstrained_state(project, unconstrained_state):
    """
    Process an unconstrained state and extract gadgets from it.
    """
    instruction_addr = unconstrained_state.regs.ip
    controlled_registers = analyse_controlled_registers(project, unconstrained_state.copy(), instruction_addr)

    addr = unconstrained_state.solver.eval(instruction_addr)
    block = project.factory.block(addr=addr)
    num_ins = block.instructions

    if num_ins > 0:
        gadget = Gadget(instruction_addr, block.pp, num_ins, controlled_registers)
        return [gadget]
    
    return []

