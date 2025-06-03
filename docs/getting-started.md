# Getting Started with WERL

## Introduction

The WebKit Exploit Research Library (WERL) is a comprehensive toolkit designed for security researchers, bug bounty hunters, and penetration testers working on WebKit-based browser vulnerabilities. This guide will help you get started with the library and understand its core concepts.

## 🚨 Important Security Notice

**WERL is intended for authorized security research only.** Before using this library:

1. ✅ Ensure you have explicit permission to test the target system
2. ✅ Follow responsible disclosure practices for any vulnerabilities discovered
3. ✅ Use only in controlled environments for educational purposes
4. ❌ Do not use for malicious purposes or unauthorized access
5. ❌ Do not use on systems you don't own or have permission to test

## Installation

### Browser Environment

1. **Download the library:**
   ```bash
   git clone https://github.com/security-research/werl.git
   cd werl
   ```

2. **Include in your HTML:**
   ```html
   <script src="werl.js"></script>
   ```

3. **Start using:**
   ```javascript
   // WERL is automatically initialized
   console.log(werl.version); // "1.0.0"
   ```

### Local Development Server

For security reasons, many browser features require HTTPS or localhost. Start a local server:

```bash
# Using Python 3
python3 -m http.server 8080

# Using Node.js
npx http-server

# Using PHP
php -S localhost:8080
```

Then visit `http://localhost:8080/examples/` for interactive examples.

## Core Concepts

### Memory Management

WERL provides sophisticated memory management utilities for heap manipulation:

```javascript
// Heap grooming - prepare heap with specific object sizes
const objects = werl.memory.groomHeap(0x100, 50);

// Heap spraying - fill memory with controlled patterns
const arrays = werl.memory.heapSpray(0x1000, 0x41414141, 100);

// Create holes in heap layout
werl.memory.createHoles(objects, 'every_other');

// Force garbage collection
werl.memory.forceGC();
```

### Object Inspection

Deep analysis of JavaScript objects and their internal structure:

```javascript
// Analyze any object
const analysis = werl.inspect.analyzeObject(document);
console.log(`Object has ${analysis.properties.length} properties`);

// Visualize memory layout
werl.inspect.visualizeLayout([obj1, obj2, obj3]);

// Estimate object sizes
const size = werl.inspect.estimateSize(myObject);
```

### ROP Chain Building

Construct Return-Oriented Programming chains:

```javascript
// Build ROP chain
const chain = werl.rop.buildChain([
    werl.rop.gadgets.popRdi,
    0x41414141,
    werl.rop.gadgets.ret
]);

// Find gadgets
const gadgets = werl.rop.findGadgets('pop');

// Validate chain
const validation = werl.rop.validateChain(chain);
```

### Debugging and Utilities

Advanced debugging and utility functions:

```javascript
// Hexdump binary data
werl.debug.hexdump(buffer);

// Track memory usage
werl.debug.trackMemory();

// Generate exploit patterns
const pattern = werl.utils.cyclicPattern(100);
const offset = werl.utils.findOffset(pattern, 'DEFG');

// Pack/unpack integers
const bytes = werl.utils.pack32(0x41414141);
const num = werl.utils.unpack32(bytes);
```

## Common Use Cases

### 1. Buffer Overflow Research

```javascript
// Generate cyclic pattern for buffer overflow
const pattern = werl.utils.cyclicPattern(1000);
console.log('Send this pattern to find offset:', pattern);

// When you get a crash, find the offset
const crashValue = 'FAAB'; // Example crash data
const offset = werl.utils.findOffset(pattern, crashValue);
console.log(`Offset: ${offset}`);

// Build ROP chain for exploitation
const ropChain = werl.rop.buildChain([
    werl.rop.gadgets.popRdi,
    0x7fffffff1000,  // Address of "/bin/sh"
    werl.rop.gadgets.ret
]);
```

### 2. Heap Vulnerability Research

```javascript
// Prepare heap for vulnerability research
console.log('Setting up heap layout...');

// Phase 1: Initial grooming
const initial = werl.memory.groomHeap(0x100, 200);

// Phase 2: Create controlled holes
werl.memory.createHoles(initial, 'every_other');

// Phase 3: Fill with spray objects
const spray = werl.memory.heapSpray(0x200, 0xdeadbeef, 100);

// Phase 4: Trigger vulnerability
// (Your vulnerability trigger code here)

// Phase 5: Verify heap layout
werl.inspect.visualizeLayout(spray.slice(0, 10));
```

### 3. Type Confusion Analysis

```javascript
// Create objects for type confusion research
const confused = werl.webkit.createConfusedTypes();

// Analyze each object's structure
confused.forEach((obj, index) => {
    const analysis = werl.inspect.analyzeObject(obj);
    console.log(`Object ${index}: ${analysis.constructor}`);
    console.log(`  Properties: ${analysis.properties.length}`);
    console.log(`  Size: ${analysis.size} bytes`);
});

// Create polymorphic function
function polymorphic(obj) {
    return obj.length || obj.byteLength || 0;
}

// Test with different types
confused.forEach(obj => {
    try {
        console.log(`Result: ${polymorphic(obj)}`);
    } catch (e) {
        console.log(`Type confusion: ${e.message}`);
    }
});
```

### 4. JIT Compiler Research

```javascript
// Analyze JIT compilation
const jitInfo = werl.webkit.analyzeJIT();
console.log('JIT analysis:', jitInfo);

// Create function for JIT spray
function sprayFunction(x) {
    // Controlled constants that will be JIT compiled
    const a = 0x41414141;
    const b = 0x42424242;
    return (a ^ b) + x;
}

// Warm up the function to trigger JIT
for (let i = 0; i < 10000; i++) {
    sprayFunction(i);
}

console.log('JIT spray function prepared');
```

### 5. Information Disclosure

```javascript
// Probe system information
const engineInfo = werl.webkit.getEngineInfo();
console.log('Browser engine info:', engineInfo);

// Analyze important objects
const windowAnalysis = werl.inspect.analyzeObject(window, 2);
console.log(`Window has ${windowAnalysis.properties.length} properties`);

// Look for sensitive data
const sensitiveProps = windowAnalysis.properties.filter(prop => 
    prop.name.includes('password') || 
    prop.name.includes('token') || 
    prop.name.includes('secret')
);

if (sensitiveProps.length > 0) {
    console.log('⚠️ Potentially sensitive properties found:', sensitiveProps);
}
```

## Advanced Techniques

### Use-After-Free Simulation

```javascript
// Create victim objects
const victims = [];
for (let i = 0; i < 100; i++) {
    victims.push({
        id: i,
        data: new Array(64).fill(0x41414141)
    });
}

// Free objects (simulate UAF condition)
werl.memory.createHoles(victims, 'every_other');

// Allocate confusing objects in freed slots
const confused = werl.webkit.createConfusedTypes();

// Attempt to use freed objects (controlled simulation)
for (let i = 1; i < victims.length; i += 2) {
    if (victims[i] === null) {
        console.log(`Object ${i} was freed`);
        // In real UAF, this would be a dangling pointer
    }
}
```

### Heap Feng Shui

```javascript
// Precise heap layout control
console.log('Performing Heap Feng Shui...');

// Create specific heap layout patterns
const sizes = [0x80, 0x100, 0x200, 0x400];
const layouts = {};

sizes.forEach(size => {
    layouts[size] = werl.memory.groomHeap(size, 50);
});

// Create controlled holes in specific patterns
Object.values(layouts).forEach(objects => {
    werl.memory.createHoles(objects, 'middle');
});

// Fill holes with exploit objects
const exploitObjects = werl.memory.heapSpray(0x150, 0xcafebabe, 25);

console.log('Heap Feng Shui complete');
werl.debug.trackMemory();
```

## Best Practices

### 1. Memory Management

```javascript
// Always clean up after experiments
function cleanupExperiment() {
    werl.memory.cleanup();
    werl.debug.trackMemory();
}

// Monitor memory usage during research
function monitoredResearch(researchFunction) {
    console.log('Before:', werl.debug.trackMemory());
    
    const result = researchFunction();
    
    console.log('After:', werl.debug.trackMemory());
    return result;
}
```

### 2. Safe Experimentation

```javascript
// Use try-catch for dangerous operations
function safeExperiment(dangerousFunction) {
    try {
        return dangerousFunction();
    } catch (error) {
        console.log(`Experiment failed safely: ${error.message}`);
        werl.debug.trackMemory();
        return null;
    }
}

// Time your experiments
function timedExperiment(name, experimentFunction) {
    return werl.debug.timeFunction(experimentFunction, name);
}
```

### 3. Documentation

```javascript
// Always document your research
function documentedResearch(description, researchFunction) {
    werl.debug.log(`Starting: ${description}`);
    
    const startTime = performance.now();
    const result = researchFunction();
    const endTime = performance.now();
    
    werl.debug.log(`Completed: ${description} (${endTime - startTime}ms)`);
    return result;
}
```

## Troubleshooting

### Common Issues

1. **Memory Limits**: Browser memory limits may prevent large heap sprays
   ```javascript
   // Use smaller chunks and monitor memory
   werl.debug.trackMemory();
   ```

2. **Garbage Collection**: Objects may be collected unexpectedly
   ```javascript
   // Force GC at controlled times
   werl.memory.forceGC();
   ```

3. **Security Restrictions**: Some browsers block certain operations
   ```javascript
   // Check for available APIs
   if (window.gc) {
       console.log('GC function available');
   } else {
       console.log('GC function not available');
   }
   ```

### Performance Tips

1. **Batch Operations**: Group similar operations together
2. **Monitor Memory**: Regularly check memory usage
3. **Clean Up**: Always clean up after experiments
4. **Use Patterns**: Reuse proven patterns and techniques

## Next Steps

1. **Explore Examples**: Check out the `examples/` directory for hands-on demonstrations
2. **Read API Reference**: See `docs/api-reference.md` for complete API documentation
3. **Practice Safely**: Always use WERL in controlled, authorized environments
4. **Stay Updated**: Follow responsible disclosure practices for any discoveries

## Getting Help

- 📚 **Documentation**: Check the `docs/` directory
- 💻 **Examples**: Interactive examples in `examples/`
- 🐛 **Issues**: Report bugs on the project repository
- 💬 **Community**: Join security research communities for discussion

Remember: **Use WERL responsibly and ethically for authorized security research only.** 