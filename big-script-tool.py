from optparse import OptionParser, make_option

import re
import struct

INSTR_LEN = 8
MAX_OPERANDS = 3
OPCODE_LEN = 2

OP1_NUM = 0
OP2_NUM = 1
OP3_NUM = 2

#
# @TODO: take it out of here (json probably)
#
opcodes = {
    0x00: { 'name': 'nop',
            'operands': ['unused', 'unused', 'unused'] },
    0x01: { 'name': 'begin',
            'operands': ['unused', 'unused', 'unused'] },
    0x10: { 'name': 'write',
            'operands': ['flash', 'buff', 'reg'] },
    0x11: { 'name': 'write',
            'operands': ['flash', 'buff', 'imm'] },
    0x12: { 'name': 'read',
            'operands': ['buff', 'flash', 'reg'] },
    0x13: { 'name': 'read',
            'operands': ['buff', 'flash', 'imm'] },
    0x14: { 'name': 'eraseblk',
            'operands': ['flash', 'unused', 'unused'] },
    0x15: { 'name': 'erase64kblk',
            'operands': ['flash', 'unused', 'unused'] },
    0x20: { 'name': 'eccmdwr',
            'operands': ['reg', 'unused', 'unused'] },
    0x21: { 'name': 'eccmdwr',
            'operands': ['unused', 'unused', 'imm'] },
    0x22: { 'name': 'ecstsrd',
            'operands': ['reg', 'unused', 'unused'] },
    0x23: { 'name': 'ecdatawr',
            'operands': ['reg', 'unused', 'unused'] },
    0x24: { 'name': 'ecdatawr',
            'operands': ['unused', 'unused', 'imm'] },
    0x25: { 'name': 'ecdatard',
            'operands': ['reg', 'unused', 'unused'] },
    0x30: { 'name': 'add',
            'operands': ['reg', 'reg', 'unused'] },
    0x31: { 'name': 'add',
            'operands': ['reg', 'unused', 'imm'] },
    0x32: { 'name': 'add',
            'operands': ['buff', 'reg', 'unused'] },
    0x33: { 'name': 'add',
            'operands': ['buff', 'unused', 'imm'] },
    0x34: { 'name': 'add',
            'operands': ['flash', 'reg', 'unused'] },
    0x35: { 'name': 'add',
            'operands': ['flash', 'unused', 'imm'] },
    0x36: { 'name': 'sub',
            'operands': ['reg', 'reg', 'unused'] },
    0x37: { 'name': 'sub',
            'operands': ['reg', 'unused', 'imm'] },
    0x38: { 'name': 'sub',
            'operands': ['buff', 'reg', 'unused'] },
    0x39: { 'name': 'sub',
            'operands': ['buff', 'unused', 'imm'] },
    0x3a: { 'name': 'sub',
            'operands': ['flash', 'reg', 'unused'] },
    0x3b: { 'name': 'sub',
            'operands': ['flash', 'unused', 'imm'] },
    0x40: { 'name': 'and',
            'operands': ['reg', 'reg', 'unused'] },
    0x41: { 'name': 'and',
            'operands': ['reg', 'unused', 'imm'] },
    0x42: { 'name': 'or',
            'operands': ['reg', 'reg', 'unused'] },
    0x43: { 'name': 'or',
            'operands': ['reg', 'unused', 'imm'] },
    0x44: { 'name': 'shiftr',
            'operands': ['reg', 'unused', 'imm'] },
    0x45: { 'name': 'shiftl',
            'operands': ['reg', 'unused', 'imm'] },
    0x46: { 'name': 'rotater',
            'operands': ['reg', 'unused', 'imm'] },
    0x47: { 'name': 'rotatel',
            'operands': ['reg', 'unused', 'imm'] },
    0x50: { 'name': 'set',
            'operands': ['reg', 'reg', 'unused'] },
    0x51: { 'name': 'set',
            'operands': ['reg', 'unused', 'imm'] },
    0x52: { 'name': 'set',
            'operands': ['buff', 'reg', 'unused'] },
    0x53: { 'name': 'set',
            'operands': ['buff', 'unused', 'imm'] },
    0x54: { 'name': 'set',
            'operands': ['flash', 'reg', 'unused'] },
    0x55: { 'name': 'set',
            'operands': ['flash', 'unused', 'imm'] },
    0x60: { 'name': 'loadbyte',
            'operands': ['reg', 'buff', 'unused'] },
    0x61: { 'name': 'loadword',
            'operands': ['reg', 'buff', 'unused'] },
    0x62: { 'name': 'loaddword',
            'operands': ['reg', 'buff', 'unused'] },
    0x63: { 'name': 'storebyte',
            'operands': ['buff', 'reg', 'unused'] },
    0x64: { 'name': 'storeword',
            'operands': ['buff', 'reg', 'unused'] },
    0x65: { 'name': 'storedword',
            'operands': ['buff', 'reg', 'unused'] },
    0x70: { 'name': 'compare',
            'operands': ['reg', 'reg', 'unused'] },
    0x71: { 'name': 'compare',
            'operands': ['reg', 'unused', 'imm'] },
    0x72: { 'name': 'compare',
            'operands': ['buff', 'reg', 'unused'] },
    0x73: { 'name': 'compare',
            'operands': ['buff', 'unused', 'imm'] },
    0x74: { 'name': 'compare',
            'operands': ['flash', 'reg', 'unused'] },
    0x75: { 'name': 'compare',
            'operands': ['flash', 'unused', 'imm'] },
    0x76: { 'name': 'compare',
            'operands': ['buff', 'buff', 'reg'] },
    0x77: { 'name': 'compare',
            'operands': ['buff', 'buff', 'imm'] },
    0x80: { 'name': 'copy',
            'operands': ['buff', 'buff', 'reg'] },
    0x81: { 'name': 'copy',
            'operands': ['buff', 'buff', 'imm'] },
    0x90: { 'name': 'jmp',
            'operands': ['unused', 'unused', 'imm'] },
    0x91: { 'name': 'je',
            'operands': ['unused', 'unused', 'imm'] },
    0x92: { 'name': 'jne',
            'operands': ['unused', 'unused', 'imm'] },
    0x93: { 'name': 'jg',
            'operands': ['unused', 'unused', 'imm'] },
    0x94: { 'name': 'jge',
            'operands': ['unused', 'unused', 'imm'] },
    0x95: { 'name': 'jl',
            'operands': ['unused', 'unused', 'imm'] },
    0x96: { 'name': 'jle',
            'operands': ['unused', 'unused', 'imm'] },
    0x97: { 'name': 'jmp',
            'operands': ['reg', 'unused', 'unused'] },
    0xa0: { 'name': 'log',
            'operands': ['imm', 'reg', 'unused'] },
    0xa1: { 'name': 'log',
            'operands': ['imm', 'unused', 'imm'] },
    0xb0: { 'name': 'rdsts',
            'operands': ['reg', 'unused', 'unused'] },
    0xb1: { 'name': 'rdkeyslot',
            'operands': ['reg', 'unused', 'unused'] },
    0xb2: { 'name': 'rdrand',
            'operands': ['reg', 'unused', 'unused'] },
    0xc0: { 'name': 'stall',
            'operands': ['unused', 'unused', 'imm'] },
    0xc1: { 'name': 'rdts',
            'operands': ['reg', 'unused', 'unused'] },
    0xc2: { 'name': 'setts',
            'operands': ['unused', 'unused', 'unused'] },
    0xc3: { 'name': 'clearts',
            'operands': ['unused', 'unused', 'unused'] },
    0xff: { 'name': 'end',
            'operands': ['unused', 'unused', 'unused'] }
}

class BigScript:
    def __init__(self, code_string = None, code_bytes = None):
        global opcodes

        self.instructions = []
        self.op_dict = opcodes

        if not code_string is None:
            self.assemble(code_string)
            self.code_string = code_string
        elif not code_bytes is None:
            self.disassemble(code_bytes)
            self.code_bytes = code_bytes

    def assemble(self, code_string):
        all_lines = [line.strip() for line in code_string.splitlines()]
        labels = {}

        # remove labels from code listing and replace it with actual line numbers
        offset = 0
        for i in range(0, len(all_lines)):
            if all_lines[i][0] == '_':
                labels[all_lines[i]] = i-offset
                offset+=1

        code_lines = [line for line in all_lines if not line[0] == '_']                
        code_lines_count = len(code_lines)
        for i in range(0, code_lines_count):
            line = code_lines[i]
            for label in labels:
                if label in line:
                    code_lines[i] = line.replace(label, str(labels[label]))

        
        self.instructions = [Instruction(self.op_dict, i*INSTR_LEN, instr_string=code_lines[i]) for i in range(0, code_lines_count)]

        if not self.instructions[0].is_start():
            print('WARNING: the input script doesn\'t start with `begin` opcode. ACM will reject this script.')
        if not self.instructions[-1].is_end():
            print('WARNING: the input script doesn\'t end with `end` opcode. ACM will reject this script.')

        self.code_bytes = b''
        for instr in self.instructions:
            self.code_bytes += instr.to_bytes()

    def disassemble(self, code_bytes):
        code_len = len(code_bytes)
        if not code_len % INSTR_LEN == 0:
            raise Exception('ERROR: code size need to be aligned to 8. The input script is corrupted.')

        code_lines_count = code_len // INSTR_LEN
        code_lines = [code_bytes[i:i + INSTR_LEN] for i in range(0, code_len, INSTR_LEN)]
        self.instructions = [Instruction(self.op_dict, i*INSTR_LEN, instr_bytes=code_lines[i]) for i in range(0, code_lines_count)]

        if not self.instructions[0].is_start():
            print('WARNING: the input script doesn\'t start with `begin` opcode. It may be corrupted.')
        if not self.instructions[-1].is_end():
            print('WARNING: the input script doesn\'t end with `end` opcode. It may be corrupted.')

        labels = []
        for instr in [instr for instr in self.instructions if instr.is_jump()]:
            label_addr = instr.get_jump_line()
            if not label_addr in labels:
                labels.append(label_addr)
        
        code_str_lines = []
        for instr in self.instructions:
            if instr.is_jump():
                code_str_lines.append('\t' + instr.get_opcode_name() + ' ' + '_lb' + str(instr.get_jump_line()))
            else:
                code_str_lines.append('\t' + instr.to_string())

        labels.sort()
        offset = 0
        for label in labels:
            code_str_lines.insert(label+offset, '_lb'+str(label)+':')
            offset+=1

        self.code_str = '\n'.join(code_str_lines)

    def to_string(self):
        return self.code_str

    def to_bytes(self):
        return self.code_bytes


class Instruction:
    def __init__(self, opcodes_dict, instr_addr, instr_string = None, instr_bytes = None):
        self.op_dict = opcodes_dict
        self.addr = instr_addr
        self.opcode_name = ""
        self.opcode_num = None
        self.operands = [None, None, None]

        if not instr_string is None:
            self.assemble(instr_string)
            self.instr_str = instr_string
        elif not instr_bytes is None:
            self.disassemble(instr_bytes)
            self.instr_bytes = instr_bytes

    def assemble(self, instr_string):
        instr_str_splt = [part.strip() for part in instr_string.split()]
        self.opcode_name = instr_str_splt[0]

        operands_str = instr_str_splt[1:]
        operands_count = len(operands_str)
        used_operands_mask = []
        for i in range(0, operands_count):
            op = Operand(self.addr, operands_str[i])
            used_operands_mask.append(op.get_type())
            self.operands[i] = op

        # proccessing the case of various opcodes with same names
        for current_op_num in self.op_dict:
            opcode = self.op_dict[current_op_num]
            if opcode['name'] == self.opcode_name:
                used_ops = [op for op in opcode['operands'] if not op == 'unused']
                if used_ops == used_operands_mask:
                    true_operands_mask = opcode['operands']
                    self.opcode_num = current_op_num

        if self.opcode_num is None:
            raise Exception('ERROR: unknown opcode ' + self.opcode_name + ' with operands ' + str(used_operands_mask) + ' at ' + '0x%X' % self.addr + '')

        # fix operands numbers
        for i in range(0, operands_count):
            operand = self.operands[i]

            if operand.get_type() == true_operands_mask[i]:
                continue

            for j in range(i, MAX_OPERANDS):
                if true_operands_mask[j] == operand.get_type():
                    operand.set_num(j)
                    tmp = self.operands[j]
                    self.operands[j] = operand
                    self.operands[i] = tmp

        for i in range(0, MAX_OPERANDS):
            if self.operands[i] is None:
                self.operands[i] = Operand(self.addr, op_num=i)
                self.operands[i].set_type('unused')
                self.operands[i].set_value(0)

        self.instr_bytes = struct.pack('HBBI', self.opcode_num, self.operands[0].get_value(), self.operands[1].get_value(), self.operands[2].get_value())

    def disassemble(self, instr_bytes):
        self.opcode_num, op1, op2, op3 = struct.unpack('HBBI', instr_bytes)

        if not self.opcode_num in self.op_dict:
            raise Exception('ERROR: unknown opcode ' + '0x%X' % self.opcode_num + ' at ' + '0x%X' % self.addr + '')

        instr_dict = self.op_dict[self.opcode_num]
        self.operands[OP1_NUM] = Operand(self.addr, op_value=op1, op_num=OP1_NUM, root_instr_dict=instr_dict)
        self.operands[OP2_NUM] = Operand(self.addr, op_value=op2, op_num=OP2_NUM, root_instr_dict=instr_dict)
        self.operands[OP3_NUM] = Operand(self.addr, op_value=op3, op_num=OP3_NUM, root_instr_dict=instr_dict)
        self.opcode_name = self.op_dict[self.opcode_num]['name']

        self.instr_str = self.opcode_name
        for op in self.operands:
            if not op.is_unused():
                self.instr_str += ' ' + op.to_string()


    def to_bytes(self):
        return self.instr_bytes

    def to_string(self):
        return self.instr_str

    def is_start(self):
        # @TODO: make it not that ugly
        return self.opcode_num == 0x1

    def is_end(self):
        # @TODO: make it not that ugly
        return self.opcode_num == 0xff

    def is_jump(self):
        # @TODO: make it not that ugly
        return self.opcode_name[0] == 'j'

    def get_operand(self, num):
        return self.operands[num]

    def get_opcode_name(self):
        return self.opcode_name

    def get_jump_line(self):
        if self.is_jump():
            return self.get_operand(OP3_NUM).get_value()

class Operand:
    def __init__(self, root_instr_addr, op_string = None, op_value = None, op_num = None, root_instr_dict = None):
        self.instr_dict = root_instr_dict
        self.instr_addr = root_instr_addr
        self.op_type = None
        self.op_str = None
        self.op_value = op_value
        self.op_num = op_num

        if not op_string is None:
            self.assemble(op_string)
            self.op_str = op_string
        elif not op_value is None:
            self.disassemble(op_value)
            self.op_value = op_value

    def assemble(self, op_string):
        first_chr = op_string[0]
        if first_chr == 'f':
            self.op_type = 'flash'
        elif first_chr == 'b':
            self.op_type = 'buff'
        elif first_chr == 'r':
            self.op_type = 'reg'
        elif first_chr.isdigit():
            self.op_type = 'imm'
        else:
            raise Exception('ERROR: unknown type of operand ' + op_string + ' at addr ' + '0x%X' % self.instr_addr)

        self.op_value = 0
        possible_values = re.findall('0[xX][0-9a-fA-F]+|\\d+', op_string)
        for value_str in possible_values:
            value_base = 10 + int('0x' in value_str) * 6
            value = int(value_str, value_base)
            if not value == 0:
                self.op_value = value
                break

    def disassemble(self, op_value):
        if self.instr_dict is None:
            raise Exception('ERROR: instruction dict need to be passed for operands dissasembly (addr ' + '0x%X' % self.instr_addr + ')')
        if self.op_value is None:
            raise Exception('ERROR: operand value need to be passed for operands dissasembly (addr ' + '0x%X' % self.instr_addr + ')')

        operands_mask = self.instr_dict['operands']
        self.op_type = operands_mask[self.op_num]
        if self.op_type == 'flash':
            self.op_str = 'F%X' % self.op_value
        elif self.op_type == 'buff':
            self.op_str = 'B' + str(self.op_value)
        elif self.op_type == 'reg':
            self.op_str = 'I%X' % self.op_value
        elif self.op_type == 'imm':
            self.op_str = '0x%X' % self.op_value

    def get_type(self):
        return self.op_type

    def get_num(self):
        return self.op_num

    def get_value(self):
        return self.op_value

    def set_num(self, num):
        self.op_num = num

    def set_type(self, optype):
        self.op_type = optype

    def set_value(self, value):
        self.op_value = value

    def to_string(self):
        return self.op_str

    def to_bytes(self):
        if self.op_num == OP3_NUM:
            return struct.pack('<I', self.op_value)
        else:
            return struct.pack('B', self.op_value)

    def is_unused(self):
        return self.op_type == 'unused'


def main():  
    option_list = [
        make_option('-a', '--assemble', dest = 'asm', action = 'store', default = None,
            help = 'assemble a BIOS Guard script source code file'), 

        make_option('-d', '--disassemble', dest = 'disasm', action = 'store', default = None,
            help = 'disassemble a BIOS Guard script binary file')
    ]
    parser = OptionParser(option_list = option_list)
    (options, args) = parser.parse_args()


    if not options.asm is None:
        with open(options.asm) as f:
            src = f.read()

        script = BigScript(code_string=src)
        out_file = options.asm + '_assembled.bin'
        with open(out_file, 'wb') as f:
            f.write(script.to_bytes())

        print('SUCCESS: assembled code written to ' + out_file)

        return 0

    elif not options.disasm is None:
        with open(options.disasm, 'rb') as f:
            binary = f.read()
        

        script = BigScript(code_bytes=binary)
        out_file = options.disasm + '_disassembled.txt'
        with open(out_file, 'w') as f:
            f.write(script.to_string())

        print('SUCCESS: disassembled code written to ' + out_file)
        return 0
    else:
        print('[!] No actions specified, try --help')
        return -1


if __name__ == '__main__':
    exit(main())