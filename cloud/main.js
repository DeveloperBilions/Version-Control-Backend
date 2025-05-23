async function loadModule() {
    const module = await import('./functions.js');
    // Use the imported module
}

loadModule();
