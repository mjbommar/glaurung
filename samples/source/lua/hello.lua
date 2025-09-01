-- Lua sample with various language features for bytecode analysis

-- Global variables
global_counter = 42
global_string = "Hello from Lua!"

-- Function with closure
function make_counter(start)
    local count = start or 0
    return function()
        count = count + 1
        return count
    end
end

-- Table operations
local config = {
    name = "glaurung",
    version = "1.0.0",
    features = {"parser", "analyzer", "disassembler"}
}

-- Metatable example
local mt = {
    __index = function(t, k)
        return "default"
    end,
    __tostring = function(t)
        return string.format("Config: %s v%s", t.name, t.version)
    end
}
setmetatable(config, mt)

-- Coroutine example
local co = coroutine.create(function()
    for i = 1, 3 do
        print("Coroutine iteration:", i)
        coroutine.yield(i * 2)
    end
end)

-- Main execution
function main(args)
    print(global_string)
    
    -- Use closure
    local counter = make_counter(10)
    for i = 1, 3 do
        print("Counter:", counter())
    end
    
    -- Table iteration
    print("\nFeatures:")
    for i, feature in ipairs(config.features) do
        print(string.format("  [%d] %s", i, feature))
    end
    
    -- Coroutine execution
    print("\nCoroutine results:")
    while coroutine.status(co) ~= "dead" do
        local ok, value = coroutine.resume(co)
        if ok and value then
            print("  Yielded:", value)
        end
    end
    
    -- Error handling
    local status, err = pcall(function()
        error("Intentional error for testing")
    end)
    if not status then
        print("\nCaught error:", err)
    end
    
    return 0
end

-- Module-style return
if arg then
    main(arg)
else
    return {
        main = main,
        make_counter = make_counter,
        config = config
    }
end