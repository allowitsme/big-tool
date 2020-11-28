# BIOS Guard Script tool

The tool allows you to assemble and disassemble BIOS Guard script.

## Assembly

To assemble a script, you need to use `big-script-tool.py -a <script_file>`.
Assembled script will be saved to file `<script_file>_assembled.bin`.

Also you can use class `BigScript` directly:
```
script = BigScript(code_string=src)
script.to_bytes()
```
or
```
script = BigScript()
script.assemble(src)
script.to_bytes()
```

### Operands

The operands are:
* buffers
* flash pointers
* registers
* immediate values
* labels

**Buffers**: `buffer<number_of_the_buffer>` (or `b<number_of_the_buffer>`). Storages of the data.
`buffer0` points to the actual BGUP. Other buffers are temporal.
```
set b0 0xAA00
add b0 0x1
```

**Flash pointers**: `flash<number_of_the_flash_ptr>` (or `f<number_of_the_flash_ptr>`). Stores some linear address of the flash.
```
set f0 0xA00000
sub f0 0x10
```
**Registers**: `r<number_of_the_register>` - a little storage of the temporal data.
```
set r1 0x10
set r2 0x20
add r1 r2
and r1 0x30
```
**Imm values**: `<number>` or `0x<number>` if you prefer to use hex. ***Please note***, that hex numbers are start only with `0x` prefix. If you write something like `10000h` it will be interpreted as a decimal number.

**Labels**: `_<name_of_the_label>` - an arbitrary script line name. Can be used only in control flow instructions.
***Please note***, that labels start with `_` and must not end with symbols like `:`. If you use that symbol, you will need to refer to the label like `jmp _label:`.
```
_loop
  sub r1 r2
  cmp r1 0x0
  jne _loop
```

### Opcodes

| Opcode name | Operands | Info |
|-|-|-|
| start | - | marks the start of the script |
| store | `flash ptr, buffer, register` | write data from a buffer to the flash |
| store | `flash ptr, buffer, immediate value` | write data from a buffer to the flash |
| load | `buffer, flash ptr, register` | read data from the flash to the buffer |
| load | `buffer, flash ptr, immediate value` | read data from the flash to the buffer |
| eraseblk | `flash ptr` | Erase flash blk |
| eraseblk64kb | `flash ptr` | Erase 64kb flash block |
| add | `register, register` | |
| add | `register, immediate value` | |
| add | `buffer, register` | |
| add | `buffer, immediate value` | |
| add | `flash ptr, register` | |
| add | `flash ptr, immediate value` | |
| sub | `register, register` | |
| sub | `register, immediate value` | |
| sub | `buffer, register` | |
| sub | `buffer, immediate value` | |
| sub | `flash ptr, register` | |
| sub | `flash ptr, immediate value` | |
| and | `register, register` | |
| and | `register, immediate value` | |
| or | `register, register` | |
| or | `register, immediate value` | |
| shr | `register, immediate value` | |
| shl | `register, immediate value` | |
| ror | `register, immediate value` | |
| rol | `register, immediate value` | |
| set | `register, register` | |
| set | `register, immediate value` | |
| set | `buffer, register` | Set an offset from the beggining of the buffer |
| set | `buffer, immediate value` | Set an offset from the beggining of the buffer |
| set | `flash ptr, register` | Set a linear address of the flash |
| set | `flash ptr, immediate value` | Set a linear address of the flash |
| loadbyte | `register, buffer` | |
| loadword | `register, buffer` | |
| loaddword | `register, buffer` | |
| storebyte | `buffer, register` | |
| storeword | `buffer, register` | |
| storedword | `buffer, register` | |
| cmp | `register, register` | |
| cmp | `register, immediate value` | |
| cmp | `buffer, register` | |
| cmp | `buffer, immediate value` | |
| cmp | `flash ptr, register` | |
| cmp | `flash ptr, immediate value` | |
| cmp | `buffer, buffer, register` | Compare buffers with specified length |
| cmp | `buffer, buffer, immediate value` | Compare buffers with specified length |
| copy | `buffer, buffer, register` | Copy data with the specified length |
| copy | `buffer, buffer, immediate value` | Copy data with the specified length |
| jmp | `label` (or `imm`) | Uncoditional jump to the label. Also you can use a line number directly. |
| je | `label` (or `imm`)  | Coditional jump to the label. Also you can use a line number directly.|
| jne | `label`(or `imm`)  | Coditional jump to the label. Also you can use a line number directly. |
| jg | `label` (or `imm`)  | Coditional jump to the label. Also you can use a line number directly. |
| jge | `label` (or `imm`)  | Coditional jump to the label. Also you can use a line number directly. |
| jl | `label` (or `imm`)  | Coditional jump to the label. Also you can use a line number directly. |
| jle | `label` (or `imm`)  | Coditional jump to the label. Also you can use a line number directly. |
| jmp | `register` | Uncoditional jump to the line number stored in register. |
| log | `immediate value, register` | Write data from second operand to the BiG Log. The BiG log needs to be setup properly. |
| log | `immediate value, immediate value` | Write data from second operand to the BiG Log. The BiG log needs to be setup properly. |
| rdsts | `register` | Read status of previous operation into register. |
| rand | `register` | |
| sleep | `immediate value` | |
| end | - | |


## Disassembly

To disassemble a script, you need to use `big-script-tool.py -d <script_file>`.
Disassembled script will be saved to file `<script_file>_disassembled.txt`.

Also you can use class `
BigScript` directly:
```
script = BigScript(code_bytes=bin_script)
script.to_string()
```
or
```
script = BigScript()
script.disassemble(bin_script)
script.to_string()
```
