import time
import functools
from config_utils import load_config
from gadget import Gadget
import re
import signal
import functools

class TimeoutError(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutError("Function execution timed out.")

def timeout_decorator(timeout):
    def wrapper(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout)  # Set the alarm
            try:
                result = func(*args, **kwargs)
                signal.alarm(0)  # Reset the alarm
                return result
            except TimeoutError:
                if func.__name__ == "_check_regain_control":
                    return False, None
                elif func.__name__ in ["_create_gadgets", "_solve_constraints", "_analyze_return_type", "_process_unconstrained_state", "_process_return_control", "find_cmp_instruction_register"]:
                    return None
                elif func.__name__ in ["_check_sp_changed"]:
                    return 0
                elif func.__name__ in ["_find_constraints", "analysze"]:
                    return []
                else:
                    return None
            except Exception as e:
                signal.alarm(0)  # Reset the alarm in case of other exceptions
                print(f"An exception occurred in function {func.__name__}: {e}")
                raise  # Re-raise the exception
        return wrapped
    return wrapper






class GadgetAnalyzer:
    def __init__(self, project):
        self.project = project
        self.config = load_config()
    @timeout_decorator(5)
    def analyze(self, unconstrained_state, mode):
  

        def exit_early_if(condition):
            return condition  # Return the condition result directly

        result = self._process_unconstrained_state(unconstrained_state)
        if exit_early_if(not result):
            return []

        addr, block_list, return_type = result
        total_instructions = sum(block.instructions for block in block_list)

        if exit_early_if(total_instructions > self.config.instruction_count):
            return []
        sp_difference = self._check_sp_changed(unconstrained_state)
        if exit_early_if(not self.config.allow_sp_change and sp_difference != 0x0):
            return []

        # block_addresses = set(block.addr for block in block_list)
        controllable_registers = self._check_ldr_from_block(
            unconstrained_state)
        if exit_early_if(self.config.controllable_registers and not controllable_registers):
            return []

        return_controllable = self._process_return_control(
            return_type, controllable_registers, unconstrained_state, block_list
        )
        if exit_early_if(self.config.return_controllable and return_controllable[0] == "false"):
            return []

        solutions = []
        constraint_register = ""
        if self.config.enable_contraint_finding:
            constraint_states = self._find_constraints(unconstrained_state)
            sorted_constraint_states = sorted(
                constraint_states, key=lambda state: state.addr)
            constraint_register = self.find_cmp_instruction_register(
                unconstrained_state) if sorted_constraint_states else ""

            solutions = [self._solve_constraints(
                state) for state in sorted_constraint_states]

            for state in sorted_constraint_states:

                result1 = self._process_unconstrained_state(state)
                if not result1:
                    continue  # Skip to the next iteration if result1 is None

                addr1, block_list1, return_type1 = result1
                block_addresses1 = set(block.addr for block in block_list1)
                new_total_instructions = sum(
                    block.instructions for block in block_list1)
                if new_total_instructions > self.config.instruction_count:
                    continue
                new_controllable_registers = self._check_ldr_from_block(state)
                if self.config.controllable_registers and not new_controllable_registers:
                    continue
                new_sp_difference = self._check_sp_changed(state)
                if not self.config.allow_sp_change and new_sp_difference != 0x0:
                    continue

                # Get new return controllable result
                new_return_controllable = self._process_return_control(
                    return_type1, controllable_registers, state, block_list1
                )
                if self.config.return_controllable and new_return_controllable[0] == "false":
                    continue
                # Extend existing return_controllable list with new result
                total_instructions += new_total_instructions
                controllable_registers.extend(new_controllable_registers)
                sp_difference += new_sp_difference
                return_controllable.extend(new_return_controllable)

                instruction_addr = state.regs.ip
                addr = state.solver.eval(instruction_addr)
                block_list.append(self._create_block(addr))

        return self._create_gadgets(
            mode, hex(addr), block_list, total_instructions, solutions,
            constraint_register, return_type, sp_difference,
            controllable_registers, return_controllable, unconstrained_state
        )
    @timeout_decorator(2)
    def _process_return_control(self, return_type, controllable_registers, unconstrained_state, block_list):
        return_controllable = self._is_return_controllable(
            return_type, controllable_registers
        )
      

        # Ensure return_controllable is a list before proceeding
        if not isinstance(return_controllable, list):
            return_controllable = [str(return_controllable).lower()]

        # Now it's safe to check the first element
        if not return_controllable or return_controllable[0] == "false":
            return_controllable, control_block = self._check_regain_control(
                unconstrained_state
            )
            # Ensure return_controllable is a list before proceeding
            if not isinstance(return_controllable, list):
                return_controllable = [str(return_controllable).lower()]

            # Now it's safe to check the first element
            if return_controllable and return_controllable[0] != "false":

                # Reassign return_controllable to a new list containing the desired string
                return_controllable = [f"@{hex(control_block.addr)}"]
                #if control_block.addr not in block_addresses:

                 #  block_addresses.add(control_block.addr)
                  # block_list.append(control_block)

        return return_controllable
    @timeout_decorator(2)
    def _create_gadgets(self, mode, addr, block_list, total_instructions, solutions, constraint_register, return_type, sp_difference, controllable_registers, return_controllable, unconstrained_state):
        constraint_register = ""
     
        if mode == "fast":
            return [Gadget(addr, block_list, total_instructions, [], [], return_type, sp_difference, controllable_registers, return_controllable)]
        # self._update_block_list_from_constraints(
        #    unconstrained_state, block_list, block_addresses)

        return [Gadget(addr, block_list, total_instructions, solutions, constraint_register, return_type, sp_difference, controllable_registers, return_controllable)]
    @timeout_decorator(2)
    def find_cmp_instruction_register(self, state):
       
        # Get the block of instructions at the state's address
        block = state.project.factory.block(state.addr)

        # Iterate through the instructions in the block
        for instr in block.capstone.insns:

            # Check if the instruction is a comparison instruction
            if instr.mnemonic == 'cmp':
                # Split the instruction operands string on commas
                operands = instr.op_str.split(',')
                # The first operand should be the first register
                first_register = operands[0].strip()
                return first_register  # return the register name

        return None  # Return None if no cmp instruction is found

    def _update_block_list_from_constraints(self, unconstrained_state, block_list, block_addresses):
       
        constraint_states = self._find_constraints(unconstrained_state)
        for state in constraint_states:
            block = self._create_block(state.solver.eval(state.regs.ip))
            if block.addr not in block_addresses:
                block_list.append(block)
                block_addresses.add(block.addr)  # Update the set of addresses
    @timeout_decorator(2)
    def _process_unconstrained_state(self, state):
       
        instruction_addr = state.regs.ip
        addr = state.solver.eval(instruction_addr)
        block_list = [self._create_block(addr)]

        if block_list and block_list[0].instructions > 1:
            return_type = self._analyze_return_type(block_list[0])
            return addr, block_list, return_type

        return None
    
   
    def _check_sp_changed(self, state):
      
        """
        Find constraint states from a given state and return the difference in xsp.
        """
        # Ensure there's an active state after the step
        successors = state.step()
        if not successors:
            return 0  # No difference since there's no new state

        # Use the first active state as the updated state
        updated_state = successors[0]

        # Calculate and return the difference in a single line

        return updated_state.solver.eval(updated_state.regs.sp) - state.solver.eval(state.regs.sp)

    @timeout_decorator(2)
    def _find_constraints(self, state):
      
        """
        Find constraint states from a given state.
        """
        # Step the state to get successors
        successors = state.step()
        # Return the active states if there are 2 or more, else return an empty list
        return successors.successors if len(successors.successors) >= 2 else []
    @timeout_decorator(2)
    def _solve_constraints(self, state):
       
        """
        Solve constraints and return the solution.
        """
        input_data = state.posix.stdin.load(0, state.posix.stdin.size)
        # solution_int = state.solver.eval(input_data, cast_to=int)
        # decode to string using latin-1 encoding
        solution_str = state.solver.eval(input_data, cast_to=bytes)
        solution = solution_str.decode('latin-1')
        # solution_str = re.sub(r'[^\x20-\x7E]', '', solution_str)  # remove all non-ASCII characters
        return solution

    def _create_block(self, addr):
       
        block = self.project.factory.block(addr=addr)
        return block
    @timeout_decorator(2)
    def _analyze_return_type(self, block):
        
        """
        Find return type.
        """
        # Get the last instruction's assembly representation
        last_instr = block.capstone.insns[-1]
        mnemonic = last_instr.mnemonic
        op_str = last_instr.op_str

        # Check if the mnemonic is 'ret' or some other jump instruction
        if mnemonic == 'ret':
            return 'ret = x30'
        elif mnemonic in [
            'b', 'bl', 'br', 'blr',
            'b.lt', 'b.le', 'b.gt', 'b.ge',  # Corrected the mnemonics
            # Added missing conditions (plus and minus)
            'b.ne', 'b.eq', 'b.pl', 'b.mi',
            # Added more conditions (overflow, no overflow, higher, lower or same)
            'b.vs', 'b.vc', 'b.hi', 'b.ls', 'b.hs',
            'cbz', 'cbnz', 'tbz', 'tbnz'
        ]:
            return f"{mnemonic} = {op_str}"
        else:
            return block.vex.jumpkind

    def _is_return_controllable(self, s, check_list):
       
        # Check if the string contains an equals sign before attempting to split
        if '=' not in s:
           
            return False  # Return False or handle this case as appropriate for your program

        # Extract the register from the string s
        register = s.split('=')[1].strip()

        # Check if the register is present in the list before the "="
        return_controllable = any(register in item.split(
            '=')[0].strip() for item in check_list if '=' in item)

        # TODO if return not controllable, step() and call check_ldr_from_block. check if control can be gained from next gadget
        return return_controllable
    
    @timeout_decorator(2)
    def _check_regain_control(self, state):
       
        successors = state.step()

        # Ensure there's an active state after the step
        if not successors.successors:
            # No difference since there's no new state, also return None for control_block
            return False, None

        # Use the first active state as the updated state
        updated_state = successors.successors[0]
        result = self._process_unconstrained_state(updated_state)
        if not result:
            return False, None  # Return None for control_block if there's no result

        addr, block_list, return_type = result
        controllable_registers = self._check_ldr_from_block(updated_state)
        return_controllable = self._is_return_controllable(
            return_type, controllable_registers)

        # Get the block for the updated state
        control_block_addr = updated_state.solver.eval(updated_state.regs.ip)
        control_block = self._create_block(control_block_addr)

        # Return control_block along with return_controllable flag
        return return_controllable, control_block

    
    def _extract_stack_offset(self, operand):
        
        if '#' in operand:
            offset = operand.split('#')[-1].strip()
            return offset.replace(']', '').strip()  # Remove any trailing ']'
        return "0"

    def _check_ldr_from_block(self, state):
       
        found = []
        block = self.project.factory.block(state.addr)
        tracked_registers = set()  # Registers holding a value or address from the stack
        register_mappings = {}     # Dictionary to track register-to-register moves

        for instr in block.capstone.insns:
            instr_disassembled = instr.mnemonic + " " + instr.op_str
            operands = instr.op_str.split(',')

            # Track register-to-register moves or loads
            if instr.mnemonic.lower() in ['mov', 'ldr'] and len(operands) == 2:
                dest_reg = operands[0].strip()
                src_reg = operands[1].strip()
                if src_reg in tracked_registers:
                    found.append(f"{dest_reg} = {src_reg}")
                    tracked_registers.add(dest_reg)
                register_mappings[dest_reg] = src_reg

            # Check for direct moves from the stack
            if 'sp' in instr_disassembled.lower():
                if instr.mnemonic.lower() == 'mov' and 'sp' in operands[1].lower():
                    dest_reg = operands[0].strip()
                    found.append(f"{dest_reg} = sp")
                    tracked_registers.add(dest_reg)

                elif instr.mnemonic.lower() == 'ldr':
                    dest_reg = operands[0].strip()
                    stack_offset = self._extract_stack_offset(
                        instr_disassembled)
                    found.append(f"{dest_reg} = [sp + {stack_offset}]")
                    tracked_registers.add(dest_reg)

                elif instr.mnemonic.lower() == 'ldp':
                    stack_offset = self._extract_stack_offset(
                        instr_disassembled)
                    for reg in operands[:2]:  # Iterate over the destination registers
                        dest_reg = reg.strip()
                        found.append(f"{dest_reg} = [sp + {stack_offset}]")
                        tracked_registers.add(dest_reg)

        return found
