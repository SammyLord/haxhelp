# WERL API Reference

## Table of Contents
- [Core WERL Class](#core-werl-class)
- [Memory Module](#memory-module)
- [Inspection Module](#inspection-module)
- [ROP Module](#rop-module)
- [Debug Module](#debug-module)
- [WebKit Module](#webkit-module)
- [Utils Module](#utils-module)

## Core WERL Class

### Constructor
```javascript
const werl = new WERL();
```

### Properties
- `version`: Library version string
- `engine`: Detected browser engine ('Safari', 'Blink', 'Unknown')
- `memory`: Memory management module
- `inspect`: Object inspection module
- `rop`: ROP chain building module
- `debug`: Debugging utilities module
- `webkit`: WebKit-specific module
- `utils`: Utility functions module

## Memory Module

### groomHeap(objectSize, count)
Prepares the heap with objects of specified size.

**Parameters:**
- `objectSize` (number): Size in bytes for each object
- `count` (number, optional): Number of objects to create (default: 100)

**Returns:** Array of created objects

**Example:**
```javascript
const objects = werl.memory.groomHeap(0x100, 50);
```

### heapSpray(size, pattern, count)
Performs heap spraying with specified pattern.

**Parameters:**
- `size` (number): Size of each spray object
- `pattern` (number, optional): Fill pattern (default: 0x41414141)
- `count` (number, optional): Number of spray objects (default: 1000)

**Returns:** Array of spray objects

**Example:**
```javascript
const arrays = werl.memory.heapSpray(0x1000, 0xdeadbeef, 100);
```

### createHoles(objects, pattern)
Creates holes in heap layout by nullifying objects.

**Parameters:**
- `objects` (Array): Array of objects to modify
- `pattern` (string, optional): Hole pattern ('every_other' or 'middle')

**Example:**
```javascript
werl.memory.createHoles(objects, 'every_other');
```

### forceGC()
Forces garbage collection.

**Example:**
```javascript
werl.memory.forceGC();
```

### alignAddress(addr, alignment)
Aligns an address to specified boundary.

**Parameters:**
- `addr` (number): Address to align
- `alignment` (number): Alignment boundary

**Returns:** Aligned address

### cleanup()
Clears all allocated objects and forces GC.

## Inspection Module

### analyzeObject(obj, maxDepth)
Performs deep analysis of JavaScript objects.

**Parameters:**
- `obj` (any): Object to analyze
- `maxDepth` (number, optional): Maximum recursion depth (default: 5)

**Returns:** Analysis object with structure:
```javascript
{
    type: string,           // Object type
    constructor: string,    // Constructor name
    prototype: string,      // Prototype constructor name
    properties: Array,      // Object properties
    methods: Array,         // Object methods
    hidden: Array,          // Hidden properties
    size: number           // Estimated size in bytes
}
```

**Example:**
```javascript
const analysis = werl.inspect.analyzeObject(document);
console.log(`Object has ${analysis.properties.length} properties`);
```

### visualizeLayout(objects)
Displays memory layout visualization in console.

**Parameters:**
- `objects` (Array): Array of objects to visualize

**Example:**
```javascript
werl.inspect.visualizeLayout([obj1, obj2, obj3]);
```

### estimateSize(obj)
Estimates the memory size of an object.

**Parameters:**
- `obj` (any): Object to measure

**Returns:** Estimated size in bytes

## ROP Module

### buildChain(instructions)
Builds a ROP chain from instructions.

**Parameters:**
- `instructions` (Array): Array of gadgets and values

**Returns:** ROP chain array

**Example:**
```javascript
const chain = werl.rop.buildChain([
    werl.rop.gadgets.popRax,
    0x41414141,
    werl.rop.gadgets.ret
]);
```

### findGadgets(pattern)
Searches for ROP gadgets matching pattern.

**Parameters:**
- `pattern` (string): Search pattern

**Returns:** Array of matching gadgets

**Example:**
```javascript
const gadgets = werl.rop.findGadgets('pop');
```

### validateChain(chain)
Validates a ROP chain for common issues.

**Parameters:**
- `chain` (Array): ROP chain to validate

**Returns:** Validation object:
```javascript
{
    valid: boolean,
    issues: Array,
    length: number
}
```

### gadgets
Built-in gadget database with common x86_64 gadgets:
- `popRax`: Pop RAX register
- `popRdi`: Pop RDI register  
- `popRsi`: Pop RSI register
- `popRdx`: Pop RDX register
- `ret`: Return instruction
- `syscall`: System call instruction

## Debug Module

### log(message, data)
Enhanced logging with timestamps.

**Parameters:**
- `message` (string): Log message
- `data` (any, optional): Additional data to log

**Example:**
```javascript
werl.debug.log('Analysis complete', analysisData);
```

### hexdump(buffer, offset, length)
Creates hexadecimal dump of buffer contents.

**Parameters:**
- `buffer` (ArrayBuffer): Buffer to dump
- `offset` (number, optional): Start offset (default: 0)
- `length` (number, optional): Length to dump (default: 256)

**Example:**
```javascript
werl.debug.hexdump(buffer, 0, 128);
```

### timeFunction(fn, name)
Measures function execution time.

**Parameters:**
- `fn` (Function): Function to time
- `name` (string, optional): Function name for logging

**Returns:** Function result

**Example:**
```javascript
const result = werl.debug.timeFunction(() => {
    // Code to measure
}, 'myFunction');
```

### trackMemory()
Displays current memory usage statistics.

**Example:**
```javascript
werl.debug.trackMemory();
```

## WebKit Module

### analyzeJIT()
Analyzes JIT compilation behavior.

**Returns:** JIT analysis object

**Example:**
```javascript
const jitInfo = werl.webkit.analyzeJIT();
```

### createConfusedTypes()
Creates objects for type confusion research.

**Returns:** Array of type-confused objects

**Example:**
```javascript
const objects = werl.webkit.createConfusedTypes();
```

### getEngineInfo()
Retrieves WebKit engine information.

**Returns:** Engine information object:
```javascript
{
    userAgent: string,
    platform: string,
    javaEnabled: boolean,
    cookieEnabled: boolean,
    onLine: boolean
}
```

## Utils Module

### toHex(num, padding)
Converts number to hexadecimal string.

**Parameters:**
- `num` (number): Number to convert
- `padding` (number, optional): Zero-padding length (default: 8)

**Returns:** Hex string with '0x' prefix

**Example:**
```javascript
const hex = werl.utils.toHex(255, 4); // "0x00ff"
```

### fromHex(hexStr)
Converts hexadecimal string to number.

**Parameters:**
- `hexStr` (string): Hex string to convert

**Returns:** Number value

### generatePattern(length, pattern)
Generates repeating pattern string.

**Parameters:**
- `length` (number): Length of pattern to generate
- `pattern` (string, optional): Base pattern (default: 'ABCD')

**Returns:** Generated pattern string

### cyclicPattern(length)
Generates cyclic pattern for overflow detection.

**Parameters:**
- `length` (number): Length of pattern

**Returns:** Cyclic pattern string

**Example:**
```javascript
const pattern = werl.utils.cyclicPattern(100);
const offset = werl.utils.findOffset(pattern, 'DEFG');
```

### findOffset(pattern, searchStr)
Finds offset of substring in pattern.

**Parameters:**
- `pattern` (string): Pattern to search in
- `searchStr` (string): String to find

**Returns:** Offset index or -1 if not found

### pack32(num) / unpack32(bytes)
Pack/unpack 32-bit integers to/from byte arrays.

**Example:**
```javascript
const bytes = werl.utils.pack32(0x41414141);
const num = werl.utils.unpack32(bytes);
```

### pack64(num) / unpack64(bytes)
Pack/unpack 64-bit integers to/from byte arrays.

**Example:**
```javascript
const bytes = werl.utils.pack64(0x4141414142424242);
const num = werl.utils.unpack64(bytes);
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Authorized Use Only**: This library is intended for authorized security research, bug bounty hunting, and penetration testing only.

2. **Responsible Disclosure**: Always follow responsible disclosure practices when discovering vulnerabilities.

3. **Performance Impact**: Some functions may significantly impact browser performance or stability.

4. **Memory Usage**: Memory-intensive operations may cause browser crashes or system instability.

5. **Legal Compliance**: Ensure you have proper authorization before using this library on any system.

## Examples

See the `examples/` directory for comprehensive usage examples and interactive demonstrations. 