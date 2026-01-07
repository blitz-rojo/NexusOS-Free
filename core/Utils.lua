-- Core/Utils.lua
-- Biblioteca de utilitários expandida - 750+ linhas

local Utils = {}

-- ============================================================================
-- SEÇÃO 1: CONSTANTES E CONFIGURAÇÕES
-- ============================================================================

Utils.Constants = {
    VERSION = "18.0-Free",
    BUILD_DATE = "2024-11-12",
    AUTHOR = "Nexus Development Team",
    LICENSE = "MIT",
    
    -- Cores do sistema
    COLORS = {
        PRIMARY = Color3.fromRGB(52, 152, 219),     -- Azul
        SECONDARY = Color3.fromRGB(46, 204, 113),   -- Verde
        DANGER = Color3.fromRGB(231, 76, 60),       -- Vermelho
        WARNING = Color3.fromRGB(241, 196, 15),     -- Amarelo
        INFO = Color3.fromRGB(41, 128, 185),        -- Azul info
        DARK = Color3.fromRGB(44, 62, 80),          -- Azul escuro
        LIGHT = Color3.fromRGB(236, 240, 241),      -- Cinza claro
        PURPLE = Color3.fromRGB(155, 89, 182),      -- Roxo
        ORANGE = Color3.fromRGB(230, 126, 34),      -- Laranja
        TEAL = Color3.fromRGB(26, 188, 156),        -- Verde água
        PINK = Color3.fromRGB(255, 105, 180),       -- Rosa
        BROWN = Color3.fromRGB(165, 105, 79),       -- Marrom
        GRAY = Color3.fromRGB(149, 165, 166)        -- Cinza
    },
    
    -- Chaves de atalho
    KEYBINDS = {
        TOGGLE_UI = Enum.KeyCode.RightControl,
        FLIGHT_UP = Enum.KeyCode.Space,
        FLIGHT_DOWN = Enum.KeyCode.LeftControl,
        SPEED_BOOST = Enum.KeyCode.LeftShift,
        NOCLIP_TOGGLE = Enum.KeyCode.N,
        ESP_TOGGLE = Enum.KeyCode.E,
        AIMBOT_TOGGLE = Enum.KeyCode.F
    },
    
    -- Configurações padrão
    DEFAULTS = {
        UI_SCALE = 1.0,
        FONT_SIZE = 14,
        ANIMATION_SPEED = 0.3,
        NOTIFICATION_DURATION = 5,
        AUTO_SAVE_INTERVAL = 60,
        MAX_HISTORY = 100,
        CACHE_SIZE = 50
    }
}

-- ============================================================================
-- SEÇÃO 2: SISTEMA DE LOGGING AVANÇADO
-- ============================================================================

Utils.LogLevels = {
    DEBUG = 1,
    INFO = 2,
    WARNING = 3,
    ERROR = 4,
    CRITICAL = 5
}

Utils.LogConfig = {
    enabled = true,
    minLevel = Utils.LogLevels.INFO,
    showTimestamp = true,
    showLevel = true,
    colors = true,
    maxHistory = 1000,
    logToFile = false,
    logFilePath = "NexusOS/logs.txt"
}

Utils.LogHistory = {}

function Utils:Log(message, level, source)
    level = level or Utils.LogLevels.INFO
    source = source or "System"
    
    -- Verificar se logging está habilitado
    if not self.LogConfig.enabled or level < self.LogConfig.minLevel then
        return
    end
    
    -- Preparar timestamp
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    
    -- Preparar nível
    local levelStr = ""
    local levelColor = ""
    
    if self.LogConfig.colors then
        if level == Utils.LogLevels.DEBUG then
            levelStr = "🐛 DEBUG"
            levelColor = "\27[36m"  -- Ciano
        elseif level == Utils.LogLevels.INFO then
            levelStr = "ℹ️ INFO"
            levelColor = "\27[34m"  -- Azul
        elseif level == Utils.LogLevels.WARNING then
            levelStr = "⚠️ WARNING"
            levelColor = "\27[33m"  -- Amarelo
        elseif level == Utils.LogLevels.ERROR then
            levelStr = "❌ ERROR"
            levelColor = "\27[31m"  -- Vermelho
        elseif level == Utils.LogLevels.CRITICAL then
            levelStr = "💀 CRITICAL"
            levelColor = "\27[35m"  -- Magenta
        end
    else
        if level == Utils.LogLevels.DEBUG then
            levelStr = "DEBUG"
        elseif level == Utils.LogLevels.INFO then
            levelStr = "INFO"
        elseif level == Utils.LogLevels.WARNING then
            levelStr = "WARNING"
        elseif level == Utils.LogLevels.ERROR then
            levelStr = "ERROR"
        elseif level == Utils.LogLevels.CRITICAL then
            levelStr = "CRITICAL"
        end
    end
    
    -- Construir mensagem
    local parts = {}
    
    if self.LogConfig.showTimestamp then
        table.insert(parts, "[" .. timestamp .. "]")
    end
    
    if self.LogConfig.showLevel then
        table.insert(parts, "[" .. levelStr .. "]")
    end
    
    table.insert(parts, "[" .. source .. "]")
    table.insert(parts, message)
    
    local formatted = table.concat(parts, " ")
    
    -- Adicionar ao histórico
    table.insert(self.LogHistory, {
        timestamp = timestamp,
        level = level,
        source = source,
        message = message,
        formatted = formatted
    })
    
    -- Limitar histórico
    if #self.LogHistory > self.LogConfig.maxHistory then
        table.remove(self.LogHistory, 1)
    end
    
    -- Output para console
    if self.LogConfig.colors then
        print(levelColor .. formatted .. "\27[0m")
    else
        print(formatted)
    end
    
    -- Log para arquivo
    if self.LogConfig.logToFile and writefile then
        self:LogToFile(formatted)
    end
    
    return formatted
end

function Utils:Debug(message, source)
    return self:Log(message, Utils.LogLevels.DEBUG, source)
end

function Utils:Info(message, source)
    return self:Log(message, Utils.LogLevels.INFO, source)
end

function Utils:Warning(message, source)
    return self:Log(message, Utils.LogLevels.WARNING, source)
end

function Utils:Error(message, source)
    return self:Log(message, Utils.LogLevels.ERROR, source)
end

function Utils:Critical(message, source)
    return self:Log(message, Utils.LogLevels.CRITICAL, source)
end

function Utils:LogToFile(message)
    if not writefile then return false end
    
    return pcall(function()
        if not isfolder("NexusOS") then
            makefolder("NexusOS")
        end
        
        local filePath = self.LogConfig.logFilePath
        local currentContent = ""
        
        if isfile(filePath) then
            currentContent = readfile(filePath) .. "\n"
        end
        
        writefile(filePath, currentContent .. message)
        return true
    end)
end

function Utils:GetLogHistory(filterLevel, filterSource, maxEntries)
    local filtered = {}
    local count = 0
    
    for i = #self.LogHistory, 1, -1 do
        local entry = self.LogHistory[i]
        
        local levelMatch = not filterLevel or entry.level >= filterLevel
        local sourceMatch = not filterSource or entry.source:find(filterSource)
        
        if levelMatch and sourceMatch then
            table.insert(filtered, entry)
            count = count + 1
            
            if maxEntries and count >= maxEntries then
                break
            end
        end
    end
    
    return filtered
end

function Utils:ClearLogHistory()
    self.LogHistory = {}
    return true
end

-- ============================================================================
-- SEÇÃO 3: SISTEMA DE CACHE AVANÇADO
-- ============================================================================

Utils.Cache = {
    data = {},
    stats = {
        hits = 0,
        misses = 0,
        sets = 0,
        evictions = 0
    },
    config = {
        maxSize = 100,
        defaultTTL = 300, -- 5 minutos
        cleanupInterval = 60 -- 1 minuto
    }
}

function Utils:CacheInit()
    -- Iniciar limpeza periódica
    self:CacheStartCleanup()
    self:Info("Sistema de cache inicializado", "Cache")
end

function Utils:CacheSet(key, value, ttl)
    ttl = ttl or self.Cache.config.defaultTTL
    
    -- Verificar se cache está cheio
    if #self.Cache.data >= self.Cache.config.maxSize then
        self:CacheEvict()
    end
    
    self.Cache.data[key] = {
        value = value,
        expires = os.time() + ttl,
        createdAt = os.time(),
        accessCount = 0
    }
    
    self.Cache.stats.sets = self.Cache.stats.sets + 1
    return true
end

function Utils:CacheGet(key)
    local item = self.Cache.data[key]
    
    if not item then
        self.Cache.stats.misses = self.Cache.stats.misses + 1
        return nil
    end
    
    -- Verificar expiração
    if os.time() > item.expires then
        self.Cache.data[key] = nil
        self.Cache.stats.misses = self.Cache.stats.misses + 1
        return nil
    end
    
    -- Atualizar estatísticas
    item.accessCount = item.accessCount + 1
    self.Cache.stats.hits = self.Cache.stats.hits + 1
    
    return item.value
end

function Utils:CacheHas(key)
    local item = self.Cache.data[key]
    if not item then return false end
    
    if os.time() > item.expires then
        self.Cache.data[key] = nil
        return false
    end
    
    return true
end

function Utils:CacheDelete(key)
    if self.Cache.data[key] then
        self.Cache.data[key] = nil
        return true
    end
    return false
end

function Utils:CacheClear()
    local count = 0
    for key in pairs(self.Cache.data) do
        self.Cache.data[key] = nil
        count = count + 1
    end
    self:Info("Cache limpo: " .. count .. " itens removidos", "Cache")
    return count
end

function Utils:CacheEvict()
    -- Encontrar item menos usado ou mais antigo
    local oldestKey = nil
    local oldestTime = math.huge
    local leastUsedKey = nil
    local minAccessCount = math.huge
    
    for key, item in pairs(self.Cache.data) do
        -- Verificar por expirados primeiro
        if os.time() > item.expires then
            self.Cache.data[key] = nil
            self.Cache.stats.evictions = self.Cache.stats.evictions + 1
            return
        end
        
        -- Encontrar mais antigo
        if item.createdAt < oldestTime then
            oldestTime = item.createdAt
            oldestKey = key
        end
        
        -- Encontrar menos usado
        if item.accessCount < minAccessCount then
            minAccessCount = item.accessCount
            leastUsedKey = key
        end
    end
    
    -- Remover baseado em política LRU
    local keyToRemove = leastUsedKey or oldestKey
    if keyToRemove then
        self.Cache.data[keyToRemove] = nil
        self.Cache.stats.evictions = self.Cache.stats.evictions + 1
        self:Debug("Item evictado do cache: " .. keyToRemove, "Cache")
    end
end

function Utils:CacheStartCleanup()
    if self._cacheCleanup then return end
    
    self._cacheCleanup = game:GetService("RunService").Heartbeat:Connect(function()
        local now = os.time()
        local removed = 0
        
        for key, item in pairs(self.Cache.data) do
            if now > item.expires then
                self.Cache.data[key] = nil
                removed = removed + 1
            end
        end
        
        if removed > 0 then
            self.Cache.stats.evictions = self.Cache.stats.evictions + removed
            self:Debug("Cleanup: " .. removed .. " itens expirados removidos", "Cache")
        end
    end)
end

function Utils:CacheStopCleanup()
    if self._cacheCleanup then
        self._cacheCleanup:Disconnect()
        self._cacheCleanup = nil
    end
end

function Utils:CacheGetStats()
    local totalSize = 0
    for _ in pairs(self.Cache.data) do
        totalSize = totalSize + 1
    end
    
    return {
        size = totalSize,
        maxSize = self.Cache.config.maxSize,
        usage = (totalSize / self.Cache.config.maxSize) * 100,
        hits = self.Cache.stats.hits,
        misses = self.Cache.stats.misses,
        hitRate = self.Cache.stats.hits / (self.Cache.stats.hits + self.Cache.stats.misses) * 100,
        sets = self.Cache.stats.sets,
        evictions = self.Cache.stats.evictions
    }
end

-- ============================================================================
-- SEÇÃO 4: SISTEMA DE EVENTOS E SIGNALS
-- ============================================================================

Utils.Signals = {}

function Utils:CreateSignal(name)
    local signal = {
        name = name or "UnnamedSignal",
        listeners = {},
        onceListeners = {},
        history = {},
        maxHistory = 50,
        enabled = true
    }
    
    function signal:Connect(callback, priority)
        priority = priority or 0
        
        local listener = {
            id = self:GenerateListenerId(),
            callback = callback,
            priority = priority,
            connected = true
        }
        
        table.insert(self.listeners, listener)
        
        -- Ordenar por prioridade
        table.sort(self.listeners, function(a, b)
            return a.priority > b.priority
        end)
        
        return {
            Disconnect = function()
                for i, l in ipairs(self.listeners) do
                    if l.id == listener.id then
                        table.remove(self.listeners, i)
                        break
                    end
                end
            end,
            Id = listener.id
        }
    end
    
    function signal:Once(callback, priority)
        local connection
        connection = self:Connect(function(...)
            connection:Disconnect()
            callback(...)
        end, priority)
        
        return connection
    end
    
    function signal:Fire(...)
        if not self.enabled then return end
        
        local args = {...}
        
        -- Adicionar ao histórico
        table.insert(self.history, {
            timestamp = os.time(),
            args = args
        })
        
        -- Limitar histórico
        if #self.history > self.maxHistory then
            table.remove(self.history, 1)
        end
        
        -- Executar listeners
        local toRemove = {}
        
        for i, listener in ipairs(self.listeners) do
            if listener.connected then
                local success, err = pcall(listener.callback, unpack(args))
                if not success then
                    Utils:Error("Erro no listener do signal '" .. self.name .. "': " .. err, "Signals")
                end
            else
                table.insert(toRemove, i)
            end
        end
        
        -- Remover listeners desconectados
        for i = #toRemove, 1, -1 do
            table.remove(self.listeners, toRemove[i])
        end
        
        return #self.listeners
    end
    
    function signal:Wait()
        local thread = coroutine.running()
        local connection
        
        connection = self:Connect(function(...)
            if connection then
                connection:Disconnect()
            end
            coroutine.resume(thread, ...)
        end)
        
        return coroutine.yield()
    end
    
    function signal:DisconnectAll()
        self.listeners = {}
        return true
    end
    
    function signal:GetListenerCount()
        return #self.listeners
    end
    
    function signal:GetHistory()
        return self.history
    end
    
    function signal:Enable()
        self.enabled = true
    end
    
    function signal:Disable()
        self.enabled = false
    end
    
    function signal:GenerateListenerId()
        return tostring(#self.listeners + 1) .. "_" .. os.time() .. "_" .. math.random(1000, 9999)
    end
    
    -- Registrar signal globalmente
    table.insert(Utils.Signals, signal)
    
    return signal
end

function Utils:GetAllSignals()
    return self.Signals
end

function Utils:DisconnectAllSignals()
    for _, signal in ipairs(self.Signals) do
        signal:DisconnectAll()
    end
    self.Signals = {}
    return true
end

-- ============================================================================
-- SEÇÃO 5: SISTEMA DE PERFORMANCE E BENCHMARK
-- ============================================================================

Utils.Performance = {
    benchmarks = {},
    monitors = {},
    config = {
        enabled = true,
        sampleRate = 1, -- segundos
        maxSamples = 1000
    }
}

function Utils:BenchmarkStart(name)
    if not self.Performance.config.enabled then return nil end
    
    self.Performance.benchmarks[name] = {
        startTime = os.clock(),
        startMemory = self:GetMemoryUsage(),
        samples = {}
    }
    
    return self.Performance.benchmarks[name]
end

function Utils:BenchmarkEnd(name)
    if not self.Performance.config.enabled or not self.Performance.benchmarks[name] then
        return nil
    end
    
    local benchmark = self.Performance.benchmarks[name]
    local endTime = os.clock()
    local endMemory = self:GetMemoryUsage()
    
    benchmark.endTime = endTime
    benchmark.endMemory = endMemory
    benchmark.duration = endTime - benchmark.startTime
    benchmark.memoryDiff = endMemory - benchmark.startMemory
    
    -- Adicionar amostra
    table.insert(benchmark.samples, {
        timestamp = os.time(),
        duration = benchmark.duration,
        memory = benchmark.memoryDiff
    })
    
    -- Limitar amostras
    if #benchmark.samples > self.Performance.config.maxSamples then
        table.remove(benchmark.samples, 1)
    end
    
    self:Debug(string.format("Benchmark '%s': %.4fs, Memory: %.2fKB", 
        name, benchmark.duration, benchmark.memoryDiff), "Performance")
    
    return benchmark
end

function Utils:BenchmarkFunction(name, func, ...)
    self:BenchmarkStart(name)
    local results = {func(...)}
    local benchmark = self:BenchmarkEnd(name)
    
    return unpack(results), benchmark
end

function Utils:StartPerformanceMonitor(name, callback, interval)
    interval = interval or self.Performance.config.sampleRate
    
    if self.Performance.monitors[name] then
        self:Warning("Monitor '" .. name .. "' já está rodando", "Performance")
        return false
    end
    
    local monitor = {
        name = name,
        interval = interval,
        running = true,
        samples = {},
        startTime = os.time()
    }
    
    local function sample()
        if not monitor.running then return end
        
        local sampleData = {
            timestamp = os.time(),
            cpuTime = os.clock(),
            memory = self:GetMemoryUsage(),
            fps = self:GetFPS(),
            ping = self:GetPing()
        }
        
        if callback then
            local success, err = pcall(callback, sampleData)
            if not success then
                self:Error("Erro no callback do monitor '" .. name .. "': " .. err, "Performance")
            end
        end
        
        table.insert(monitor.samples, sampleData)
        
        -- Limitar amostras
        if #monitor.samples > self.Performance.config.maxSamples then
            table.remove(monitor.samples, 1)
        end
        
        -- Agendar próxima amostra
        delay(interval, sample)
    end
    
    -- Iniciar sampling
    monitor.thread = coroutine.create(sample)
    coroutine.resume(monitor.thread)
    
    self.Performance.monitors[name] = monitor
    self:Info("Monitor de performance '" .. name .. "' iniciado", "Performance")
    
    return monitor
end

function Utils:StopPerformanceMonitor(name)
    local monitor = self.Performance.monitors[name]
    if not monitor then return false end
    
    monitor.running = false
    self.Performance.monitors[name] = nil
    
    self:Info("Monitor de performance '" .. name .. "' parado", "Performance")
    return true
end

function Utils:GetMemoryUsage()
    if game.Stats and game.Stats:GetTotalMemoryUsageMb then
        return game.Stats:GetTotalMemoryUsageMb() * 1024 -- Converter para KB
    end
    return 0
end

function Utils:GetFPS()
    local RunService = game:GetService("RunService")
    return math.floor(1 / RunService.RenderStepped:Wait())
end

function Utils:GetPing()
    local Stats = game:GetService("Stats")
    local network = Stats.Network
    if network then
        return network.ServerStatsItem["Data Ping"]:GetValue() or 0
    end
    return 0
end

function Utils:GetPerformanceReport()
    local report = {
        timestamp = os.time(),
        memory = self:GetMemoryUsage(),
        fps = self:GetFPS(),
        ping = self:GetPing(),
        benchmarks = {},
        monitors = {}
    }
    
    -- Coletar dados dos benchmarks
    for name, benchmark in pairs(self.Performance.benchmarks) do
        report.benchmarks[name] = {
            duration = benchmark.duration,
            memoryDiff = benchmark.memoryDiff,
            sampleCount = #benchmark.samples
        }
    end
    
    -- Coletar dados dos monitores
    for name, monitor in pairs(self.Performance.monitors) do
        report.monitors[name] = {
            running = monitor.running,
            sampleCount = #monitor.samples,
            uptime = os.time() - monitor.startTime
        }
    end
    
    return report
end

-- ============================================================================
-- SEÇÃO 6: FUNÇÕES DE SEGURANÇA E VALIDAÇÃO
-- ============================================================================

function Utils:ValidateInput(input, rules)
    if not input or not rules then return false end
    
    local errors = {}
    
    for field, rule in pairs(rules) do
        local value = input[field]
        
        -- Verificar required
        if rule.required and (value == nil or value == "") then
            table.insert(errors, field .. " é obrigatório")
        end
        
        -- Verificar tipo
        if rule.type and value ~= nil then
            local valueType = type(value)
            if rule.type == "number" and valueType ~= "number" then
                table.insert(errors, field .. " deve ser um número")
            elseif rule.type == "string" and valueType ~= "string" then
                table.insert(errors, field .. " deve ser uma string")
            elseif rule.type == "boolean" and valueType ~= "boolean" then
                table.insert(errors, field .. " deve ser um booleano")
            elseif rule.type == "table" and valueType ~= "table" then
                table.insert(errors, field .. " deve ser uma tabela")
            end
        end
        
        -- Verificar min/max para números
        if rule.min and type(value) == "number" and value < rule.min then
            table.insert(errors, field .. " deve ser no mínimo " .. rule.min)
        end
        
        if rule.max and type(value) == "number" and value > rule.max then
            table.insert(errors, field .. " deve ser no máximo " .. rule.max)
        end
        
        -- Verificar min/max length para strings
        if rule.minLength and type(value) == "string" and #value < rule.minLength then
            table.insert(errors, field .. " deve ter no mínimo " .. rule.minLength .. " caracteres")
        end
        
        if rule.maxLength and type(value) == "string" and #value > rule.maxLength then
            table.insert(errors, field .. " deve ter no máximo " .. rule.maxLength .. " caracteres")
        end
        
        -- Verificar pattern/regex
        if rule.pattern and type(value) == "string" and not value:match(rule.pattern) then
            table.insert(errors, field .. " não corresponde ao formato esperado")
        end
        
        -- Verificar enum
        if rule.enum and value ~= nil then
            local valid = false
            for _, enumValue in ipairs(rule.enum) do
                if value == enumValue then
                    valid = true
                    break
                end
            end
            if not valid then
                table.insert(errors, field .. " deve ser um dos valores: " .. table.concat(rule.enum, ", "))
            end
        end
        
        -- Validação customizada
        if rule.validate and type(rule.validate) == "function" then
            local success, err = pcall(rule.validate, value)
            if not success or err ~= true then
                table.insert(errors, field .. ": " .. tostring(err))
            end
        end
    end
    
    if #errors > 0 then
        return false, errors
    end
    
    return true
end

function Utils:SanitizeString(str, options)
    options = options or {
        trim = true,
        removeNewlines = true,
        removeSpecial = false,
        maxLength = nil,
        toLower = false,
        toUpper = false
    }
    
    if type(str) ~= "string" then return str end
    
    local sanitized = str
    
    -- Trim
    if options.trim then
        sanitized = sanitized:match("^%s*(.-)%s*$")
    end
    
    -- Remover newlines
    if options.removeNewlines then
        sanitized = sanitized:gsub("[\r\n]+", " ")
    end
    
    -- Remover caracteres especiais
    if options.removeSpecial then
        sanitized = sanitized:gsub("[^%w%s%p]", "")
    end
    
    -- Converter case
    if options.toLower then
        sanitized = sanitized:lower()
    elseif options.toUpper then
        sanitized = sanitized:upper()
    end
    
    -- Limitar tamanho
    if options.maxLength and #sanitized > options.maxLength then
        sanitized = sanitized:sub(1, options.maxLength)
    end
    
    return sanitized
end

function Utils:GenerateToken(length, includeSpecial)
    length = length or 32
    includeSpecial = includeSpecial or false
    
    local chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    if includeSpecial then
        chars = chars .. "!@#$%^&*()_+-=[]{}|;:,.<>?"
    end
    
    local token = ""
    for i = 1, length do
        local randomIndex = math.random(1, #chars)
        token = token .. chars:sub(randomIndex, randomIndex)
    end
    
    return token
end

function Utils:HashString(str, algorithm)
    algorithm = algorithm or "simple"
    
    if algorithm == "simple" then
        local hash = 0
        for i = 1, #str do
            hash = (hash * 31 + str:byte(i)) % (2^32)
        end
        return string.format("%08x", hash)
    elseif algorithm == "md5" then
        -- Implementação simplificada de MD5
        local function md5(input)
            -- Esta é uma implementação básica para exemplo
            -- Em produção, use uma biblioteca adequada
            return "md5_" .. #input .. "_hash"
        end
        return md5(str)
    end
    
    return str
end

-- ============================================================================
-- SEÇÃO 7: FUNÇÕES DE DATA E TEMPO
-- ============================================================================

function Utils:GetTimestamp()
    return os.time()
end

function Utils:FormatTime(seconds, format)
    format = format or "default"
    
    local days = math.floor(seconds / 86400)
    seconds = seconds % 86400
    
    local hours = math.floor(seconds / 3600)
    seconds = seconds % 3600
    
    local minutes = math.floor(seconds / 60)
    seconds = math.floor(seconds % 60)
    
    if format == "short" then
        if days > 0 then
            return string.format("%dd %02dh", days, hours)
        elseif hours > 0 then
            return string.format("%02dh %02dm", hours, minutes)
        elseif minutes > 0 then
            return string.format("%02dm %02ds", minutes, seconds)
        else
            return string.format("%02ds", seconds)
        end
    elseif format == "long" then
        local parts = {}
        if days > 0 then
            table.insert(parts, days .. (days == 1 and " dia" or " dias"))
        end
        if hours > 0 then
            table.insert(parts, hours .. (hours == 1 and " hora" or " horas"))
        end
        if minutes > 0 then
            table.insert(parts, minutes .. (minutes == 1 and " minuto" or " minutos"))
        end
        if seconds > 0 or #parts == 0 then
            table.insert(parts, seconds .. (seconds == 1 and " segundo" or " segundos"))
        end
        return table.concat(parts, ", ")
    else -- default
        if days > 0 then
            return string.format("%d:%02d:%02d:%02d", days, hours, minutes, seconds)
        else
            return string.format("%02d:%02d:%02d", hours, minutes, seconds)
        end
    end
end

function Utils:GetCurrentDate(format)
    format = format or "%Y-%m-%d %H:%M:%S"
    return os.date(format)
end

function Utils:ParseDate(dateStr, format)
    -- Implementação básica de parsing de data
    -- Para uma implementação completa, seria necessário usar uma biblioteca
    local patterns = {
        ["%Y-%m-%d %H:%M:%S"] = "(%d+)-(%d+)-(%d+) (%d+):(%d+):(%d+)",
        ["%d/%m/%Y %H:%M:%S"] = "(%d+)/(%d+)/(%d+) (%d+):(%d+):(%d+)",
        ["%Y%m%d_%H%M%S"] = "(%d+)_(%d+)"
    }
    
    local pattern = patterns[format]
    if not pattern then
        return nil
    end
    
    local year, month, day, hour, minute, second = dateStr:match(pattern)
    
    if year and month and day then
        local timestamp = os.time({
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour or 0),
            min = tonumber(minute or 0),
            sec = tonumber(second or 0)
        })
        return timestamp
    end
    
    return nil
end

function Utils:IsLeapYear(year)
    year = year or tonumber(os.date("%Y"))
    return (year % 4 == 0 and year % 100 ~= 0) or (year % 400 == 0)
end

function Utils:GetDaysInMonth(month, year)
    month = month or tonumber(os.date("%m"))
    year = year or tonumber(os.date("%Y"))
    
    local daysInMonth = {
        31, -- Janeiro
        self:IsLeapYear(year) and 29 or 28, -- Fevereiro
        31, -- Março
        30, -- Abril
        31, -- Maio
        30, -- Junho
        31, -- Julho
        31, -- Agosto
        30, -- Setembro
        31, -- Outubro
        30, -- Novembro
        31  -- Dezembro
    }
    
    return daysInMonth[month]
end

-- ============================================================================
-- SEÇÃO 8: FUNÇÕES MATEMÁTICAS AVANÇADAS
-- ============================================================================

function Utils:Clamp(value, min, max)
    return math.min(math.max(value, min), max)
end

function Utils:Lerp(a, b, t)
    return a + (b - a) * t
end

function Utils:InverseLerp(a, b, value)
    return (value - a) / (b - a)
end

function Utils:Remap(value, inMin, inMax, outMin, outMax)
    local t = self:InverseLerp(inMin, inMax, value)
    return self:Lerp(outMin, outMax, t)
end

function Utils:Round(value, decimals)
    decimals = decimals or 0
    local multiplier = 10 ^ decimals
    return math.floor(value * multiplier + 0.5) / multiplier
end

function Utils:Floor(value, decimals)
    decimals = decimals or 0
    local multiplier = 10 ^ decimals
    return math.floor(value * multiplier) / multiplier
end

function Utils:Ceil(value, decimals)
    decimals = decimals or 0
    local multiplier = 10 ^ decimals
    return math.ceil(value * multiplier) / multiplier
end

function Utils:Truncate(value, decimals)
    decimals = decimals or 0
    local multiplier = 10 ^ decimals
    return math.floor(value * multiplier) / multiplier
end

function Utils:Average(numbers)
    if #numbers == 0 then return 0 end
    
    local sum = 0
    for _, num in ipairs(numbers) do
        sum = sum + num
    end
    
    return sum / #numbers
end

function Utils:Median(numbers)
    if #numbers == 0 then return 0 end
    
    local sorted = {}
    for _, num in ipairs(numbers) do
        table.insert(sorted, num)
    end
    table.sort(sorted)
    
    local middle = math.floor(#sorted / 2)
    
    if #sorted % 2 == 0 then
        return (sorted[middle] + sorted[middle + 1]) / 2
    else
        return sorted[middle + 1]
    end
end

function Utils:Mode(numbers)
    if #numbers == 0 then return 0 end
    
    local counts = {}
    local maxCount = 0
    local modeValue = numbers[1]
    
    for _, num in ipairs(numbers) do
        counts[num] = (counts[num] or 0) + 1
        if counts[num] > maxCount then
            maxCount = counts[num]
            modeValue = num
        end
    end
    
    return modeValue
end

function Utils:StandardDeviation(numbers)
    if #numbers < 2 then return 0 end
    
    local avg = self:Average(numbers)
    local sumSquares = 0
    
    for _, num in ipairs(numbers) do
        sumSquares = sumSquares + (num - avg) ^ 2
    end
    
    return math.sqrt(sumSquares / (#numbers - 1))
end

function Utils:RandomNormal(mean, stdDev)
    -- Geração de número aleatório com distribuição normal (Box-Muller)
    local u1 = math.random()
    local u2 = math.random()
    
    local z0 = math.sqrt(-2 * math.log(u1)) * math.cos(2 * math.pi * u2)
    
    return mean + stdDev * z0
end

function Utils:CalculateDistance(point1, point2)
    if point1 and point2 then
        return (point1 - point2).Magnitude
    end
    return math.huge
end

function Utils:CalculateDirection(from, to)
    if from and to then
        return (to - from).Unit
    end
    return Vector3.new(0, 0, 0)
end

function Utils:IsPointInRadius(center, point, radius)
    local distance = self:CalculateDistance(center, point)
    return distance <= radius
end

function Utils:CalculateAngle(v1, v2)
    local dot = v1:Dot(v2)
    local mag1 = v1.Magnitude
    local mag2 = v2.Magnitude
    
    if mag1 == 0 or mag2 == 0 then
        return 0
    end
    
    local cosAngle = dot / (mag1 * mag2)
    cosAngle = self:Clamp(cosAngle, -1, 1)
    
    return math.deg(math.acos(cosAngle))
end

-- ============================================================================
-- SEÇÃO 9: FUNÇÕES DE STRING AVANÇADAS
-- ============================================================================

function Utils:StringStartsWith(str, prefix)
    return str:sub(1, #prefix) == prefix
end

function Utils:StringEndsWith(str, suffix)
    return str:sub(-#suffix) == suffix
end

function Utils:StringContains(str, substring, caseSensitive)
    if not caseSensitive then
        str = str:lower()
        substring = substring:lower()
    end
    return str:find(substring, 1, true) ~= nil
end

function Utils:StringCount(str, substring)
    local count = 0
    local pos = 1
    
    while true do
        local found = str:find(substring, pos, true)
        if not found then break end
        count = count + 1
        pos = found + 1
    end
    
    return count
end

function Utils:StringReverse(str)
    local reversed = ""
    for i = #str, 1, -1 do
        reversed = reversed .. str:sub(i, i)
    end
    return reversed
end

function Utils:StringPadLeft(str, length, padChar)
    padChar = padChar or " "
    while #str < length do
        str = padChar .. str
    end
    return str
end

function Utils:StringPadRight(str, length, padChar)
    padChar = padChar or " "
    while #str < length do
        str = str .. padChar
    end
    return str
end

function Utils:StringPadCenter(str, length, padChar)
    padChar = padChar or " "
    local padLength = length - #str
    local leftPad = math.floor(padLength / 2)
    local rightPad = padLength - leftPad
    
    return string.rep(padChar, leftPad) .. str .. string.rep(padChar, rightPad)
end

function Utils:StringTruncate(str, maxLength, ellipsis)
    ellipsis = ellipsis or "..."
    
    if #str <= maxLength then
        return str
    end
    
    if maxLength <= #ellipsis then
        return ellipsis:sub(1, maxLength)
    end
    
    return str:sub(1, maxLength - #ellipsis) .. ellipsis
end

function Utils:StringToTable(str, delimiter, trim)
    delimiter = delimiter or ","
    trim = trim or true
    
    local result = {}
    local pattern = "(.-)" .. delimiter
    
    local lastEnd = 1
    local s, e, cap = str:find(pattern, 1)
    
    while s do
        local item = cap
        if trim then
            item = item:match("^%s*(.-)%s*$")
        end
        table.insert(result, item)
        
        lastEnd = e + 1
        s, e, cap = str:find(pattern, lastEnd)
    end
    
    -- Último item
    local lastItem = str:sub(lastEnd)
    if trim then
        lastItem = lastItem:match("^%s*(.-)%s*$")
    end
    table.insert(result, lastItem)
    
    return result
end

function Utils:TableToString(tbl, delimiter, transform)
    delimiter = delimiter or ","
    transform = transform or tostring
    
    local parts = {}
    for _, value in ipairs(tbl) do
        table.insert(parts, transform(value))
    end
    
    return table.concat(parts, delimiter)
end

function Utils:StringFormat(template, values)
    return template:gsub("{(%w+)}", function(key)
        return tostring(values[key] or "{" .. key .. "}")
    end)
end

function Utils:GenerateRandomString(length, charset)
    charset = charset or "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local result = ""
    
    for i = 1, length do
        local randomIndex = math.random(1, #charset)
        result = result .. charset:sub(randomIndex, randomIndex)
    end
    
    return result
end

-- ============================================================================
-- SEÇÃO 10: FUNÇÕES DE TABELA AVANÇADAS
-- ============================================================================

function Utils:TableSize(tbl)
    local count = 0
    for _ in pairs(tbl) do
        count = count + 1
    end
    return count
end

function Utils:TableIsEmpty(tbl)
    return next(tbl) == nil
end

function Utils:TableKeys(tbl)
    local keys = {}
    for key in pairs(tbl) do
        table.insert(keys, key)
    end
    return keys
end

function Utils:TableValues(tbl)
    local values = {}
    for _, value in pairs(tbl) do
        table.insert(values, value)
    end
    return values
end

function Utils:TableClone(tbl, deep)
    if not deep then
        local clone = {}
        for key, value in pairs(tbl) do
            clone[key] = value
        end
        return clone
    else
        return self:DeepCopy(tbl)
    end
end

function Utils:TableMerge(t1, t2, deep)
    local result = self:TableClone(t1, deep)
    
    for key, value in pairs(t2) do
        if deep and type(value) == "table" and type(result[key]) == "table" then
            result[key] = self:TableMerge(result[key], value, deep)
        else
            result[key] = value
        end
    end
    
    return result
end

function Utils:TableFilter(tbl, predicate)
    local filtered = {}
    
    for key, value in pairs(tbl) do
        if predicate(value, key) then
            filtered[key] = value
        end
    end
    
    return filtered
end

function Utils:TableMap(tbl, transform)
    local mapped = {}
    
    for key, value in pairs(tbl) do
        mapped[key] = transform(value, key)
    end
    
    return mapped
end

function Utils:TableReduce(tbl, reducer, initial)
    local accumulator = initial
    
    for key, value in pairs(tbl) do
        if accumulator == nil then
            accumulator = value
        else
            accumulator = reducer(accumulator, value, key)
        end
    end
    
    return accumulator
end

function Utils:TableFind(tbl, predicate)
    for key, value in pairs(tbl) do
        if predicate(value, key) then
            return value, key
        end
    end
    
    return nil
end

function Utils:TableFindAll(tbl, predicate)
    local results = {}
    
    for key, value in pairs(tbl) do
        if predicate(value, key) then
            table.insert(results, {value = value, key = key})
        end
    end
    
    return results
end

function Utils:TableSortBy(tbl, key, ascending)
    ascending = ascending == nil and true or ascending
    
    local items = {}
    for _, value in pairs(tbl) do
        table.insert(items, value)
    end
    
    table.sort(items, function(a, b)
        if ascending then
            return a[key] < b[key]
        else
            return a[key] > b[key]
        end
    end)
    
    return items
end

function Utils:TableGroupBy(tbl, key)
    local groups = {}
    
    for _, item in pairs(tbl) do
        local groupKey = item[key]
        if not groups[groupKey] then
            groups[groupKey] = {}
        end
        table.insert(groups[groupKey], item)
    end
    
    return groups
end

function Utils:TableChunk(tbl, size)
    local chunks = {}
    local chunk = {}
    
    for _, value in ipairs(tbl) do
        table.insert(chunk, value)
        
        if #chunk == size then
            table.insert(chunks, chunk)
            chunk = {}
        end
    end
    
    if #chunk > 0 then
        table.insert(chunks, chunk)
    end
    
    return chunks
end

function Utils:TableFlatten(tbl, depth)
    depth = depth or math.huge
    local flattened = {}
    
    local function flatten(current, currentDepth)
        if currentDepth > depth then
            table.insert(flattened, current)
            return
        end
        
        if type(current) == "table" then
            for _, value in ipairs(current) do
                flatten(value, currentDepth + 1)
            end
        else
            table.insert(flattened, current)
        end
    end
    
    flatten(tbl, 0)
    return flattened
end

function Utils:TableShuffle(tbl)
    local shuffled = {}
    for _, value in ipairs(tbl) do
        table.insert(shuffled, value)
    end
    
    for i = #shuffled, 2, -1 do
        local j = math.random(i)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
    end
    
    return shuffled
end

function Utils:TableSample(tbl, count)
    count = count or 1
    local shuffled = self:TableShuffle(tbl)
    
    if count == 1 then
        return shuffled[1]
    else
        local samples = {}
        for i = 1, math.min(count, #shuffled) do
            table.insert(samples, shuffled[i])
        end
        return samples
    end
end

-- ============================================================================
-- SEÇÃO 11: FUNÇÕES DE ARRAY/COLEÇÃO
-- ============================================================================

function Utils:ArrayPush(array, ...)
    for _, value in ipairs({...}) do
        table.insert(array, value)
    end
    return #array
end

function Utils:ArrayPop(array)
    if #array == 0 then return nil end
    return table.remove(array)
end

function Utils:ArrayShift(array)
    if #array == 0 then return nil end
    return table.remove(array, 1)
end

function Utils:ArrayUnshift(array, ...)
    for i = select("#", ...), 1, -1 do
        table.insert(array, 1, select(i, ...))
    end
    return #array
end

function Utils:ArraySlice(array, start, finish)
    start = start or 1
    finish = finish or #array
    
    if start < 0 then
        start = #array + start + 1
    end
    
    if finish < 0 then
        finish = #array + finish + 1
    end
    
    local sliced = {}
    for i = start, finish do
        table.insert(sliced, array[i])
    end
    
    return sliced
end

function Utils:ArraySplice(array, start, deleteCount, ...)
    start = start or 1
    deleteCount = deleteCount or #array - start + 1
    
    if start < 0 then
        start = #array + start + 1
    end
    
    -- Remover elementos
    local removed = {}
    for i = 1, deleteCount do
        if array[start] then
            table.insert(removed, table.remove(array, start))
        end
    end
    
    -- Inserir novos elementos
    local insertValues = {...}
    for i = #insertValues, 1, -1 do
        table.insert(array, start, insertValues[i])
    end
    
    return removed
end

function Utils:ArrayJoin(array, separator)
    separator = separator or ","
    return table.concat(array, separator)
end

function Utils:ArrayReverse(array)
    local reversed = {}
    for i = #array, 1, -1 do
        table.insert(reversed, array[i])
    end
    return reversed
end

function Utils:ArrayIndexOf(array, value, fromIndex)
    fromIndex = fromIndex or 1
    
    for i = fromIndex, #array do
        if array[i] == value then
            return i
        end
    end
    
    return -1
end

function Utils:ArrayLastIndexOf(array, value, fromIndex)
    fromIndex = fromIndex or #array
    
    for i = fromIndex, 1, -1 do
        if array[i] == value then
            return i
        end
    end
    
    return -1
end

function Utils:ArrayIncludes(array, value)
    return self:ArrayIndexOf(array, value) ~= -1
end

function Utils:ArrayEvery(array, predicate)
    for i, value in ipairs(array) do
        if not predicate(value, i) then
            return false
        end
    end
    return true
end

function Utils:ArraySome(array, predicate)
    for i, value in ipairs(array) do
        if predicate(value, i) then
            return true
        end
    end
    return false
end

function Utils:ArrayUnique(array)
    local seen = {}
    local unique = {}
    
    for _, value in ipairs(array) do
        if not seen[value] then
            seen[value] = true
            table.insert(unique, value)
        end
    end
    
    return unique
end

function Utils:ArrayUnion(...)
    local arrays = {...}
    local union = {}
    local seen = {}
    
    for _, array in ipairs(arrays) do
        for _, value in ipairs(array) do
            if not seen[value] then
                seen[value] = true
                table.insert(union, value)
            end
        end
    end
    
    return union
end

function Utils:ArrayIntersection(...)
    local arrays = {...}
    if #arrays == 0 then return {} end
    
    local intersection = {}
    local firstArray = arrays[1]
    
    for _, value in ipairs(firstArray) do
        local inAll = true
        
        for i = 2, #arrays do
            if not self:ArrayIncludes(arrays[i], value) then
                inAll = false
                break
            end
        end
        
        if inAll then
            table.insert(intersection, value)
        end
    end
    
    return intersection
end

function Utils:ArrayDifference(array1, array2)
    local difference = {}
    local seen = {}
    
    for _, value in ipairs(array2) do
        seen[value] = true
    end
    
    for _, value in ipairs(array1) do
        if not seen[value] then
            table.insert(difference, value)
        end
    end
    
    return difference
end

-- ============================================================================
-- SEÇÃO 12: FUNÇÕES DE SERIALIZAÇÃO
-- ============================================================================

function Utils:Serialize(value, options)
    options = options or {
        indent = false,
        maxDepth = 10,
        sortKeys = true,
        prettyPrint = false
    }
    
    local visited = {}
    
    local function serializeImpl(val, depth, indentStr)
        depth = depth or 0
        
        if depth > options.maxDepth then
            return '"... (max depth reached)"'
        end
        
        local t = type(val)
        
        if t == "string" then
            return string.format("%q", val)
        elseif t == "number" then
            if val == math.huge then
                return '"Infinity"'
            elseif val == -math.huge then
                return '"-Infinity"'
            elseif val ~= val then -- NaN
                return '"NaN"'
            else
                return tostring(val)
            end
        elseif t == "boolean" then
            return val and "true" or "false"
        elseif t == "nil" then
            return "nil"
        elseif t == "table" then
            if visited[val] then
                return '"... (circular reference)"'
            end
            visited[val] = true
            
            local isArray = true
            local count = 0
            for k in pairs(val) do
                count = count + 1
                if type(k) ~= "number" or k ~= count then
                    isArray = false
                    break
                end
            end
            
            local result = {}
            local indent = options.prettyPrint and ("\n" .. string.rep(indentStr or "  ", depth + 1)) or ""
            local closingIndent = options.prettyPrint and ("\n" .. string.rep(indentStr or "  ", depth)) or ""
            
            if isArray then
                for _, v in ipairs(val) do
                    table.insert(result, serializeImpl(v, depth + 1, indentStr))
                end
                
                if options.prettyPrint then
                    return "{" .. indent .. table.concat(result, "," .. indent) .. closingIndent .. "}"
                else
                    return "{" .. table.concat(result, ",") .. "}"
                end
            else
                local keys = {}
                for k in pairs(val) do
                    table.insert(keys, k)
                end
                
                if options.sortKeys then
                    table.sort(keys, function(a, b)
                        local ta, tb = type(a), type(b)
                        if ta == tb then
                            return tostring(a) < tostring(b)
                        end
                        return ta < tb
                    end)
                end
                
                for _, k in ipairs(keys) do
                    local v = val[k]
                    local keyStr
                    
                    if type(k) == "string" and k:match("^[%a_][%w_]*$") then
                        keyStr = k
                    else
                        keyStr = "[" .. serializeImpl(k, depth + 1, indentStr) .. "]"
                    end
                    
                    table.insert(result, keyStr .. "=" .. serializeImpl(v, depth + 1, indentStr))
                end
                
                if options.prettyPrint then
                    return "{" .. indent .. table.concat(result, "," .. indent) .. closingIndent .. "}"
                else
                    return "{" .. table.concat(result, ",") .. "}"
                end
            end
        elseif t == "function" then
            return '"<function>"'
        elseif t == "userdata" or t == "thread" then
            return '"<' .. t .. '>"'
        else
            return '"<unknown type: ' .. t .. '>"'
        end
    end
    
    local result = serializeImpl(value, 0, options.indent and "  " or nil)
    visited = nil
    
    return result
end

function Utils:Deserialize(str)
    local success, result = pcall(function()
        local func, err = loadstring("return " .. str)
        if not func then
            error("Failed to compile: " .. tostring(err))
        end
        return func()
    end)
    
    if success then
        return result
    else
        self:Error("Failed to deserialize: " .. tostring(result), "Utils")
        return nil
    end
end

function Utils:ToJSON(value, pretty)
    -- Implementação simplificada de JSON
    -- Para produção, use uma biblioteca adequada
    local json = game:GetService("HttpService")
    if json then
        return json:JSONEncode(value)
    end
    
    -- Fallback manual
    return self:Serialize(value, {prettyPrint = pretty})
end

function Utils:FromJSON(str)
    local json = game:GetService("HttpService")
    if json then
        return json:JSONDecode(str)
    end
    
    -- Fallback manual
    return self:Deserialize(str)
end

-- ============================================================================
-- SEÇÃO 13: FUNÇÕES DE UTILIDADE GERAL
-- ============================================================================

function Utils:SafeCall(func, ...)
    local args = {...}
    local success, result = xpcall(function()
        return func(unpack(args))
    end, function(err)
        return debug.traceback(err, 2)
    end)
    
    if not success then
        self:Error("SafeCall failed: " .. tostring(result), "Utils")
    end
    
    return success, result
end

function Utils:Retry(func, maxRetries, delay, shouldRetry)
    maxRetries = maxRetries or 3
    delay = delay or 1
    shouldRetry = shouldRetry or function(err) return true end
    
    for attempt = 1, maxRetries do
        local success, result = self:SafeCall(func)
        
        if success then
            return result
        end
        
        if attempt < maxRetries and shouldRetry(result) then
            self:Warning(string.format("Attempt %d failed, retrying in %.1fs...", attempt, delay), "Utils")
            wait(delay)
        else
            self:Error(string.format("All %d attempts failed", maxRetries), "Utils")
            error(result)
        end
    end
end

function Utils:Debounce(func, wait)
    local lastCall = 0
    local timeout
    
    return function(...)
        local args = {...}
        local now = tick()
        
        if now - lastCall >= wait then
            lastCall = now
            return func(unpack(args))
        end
        
        if timeout then
            timeout:Disconnect()
        end
        
        timeout = game:GetService("RunService").Heartbeat:Connect(function()
            if tick() - lastCall >= wait then
                timeout:Disconnect()
                lastCall = tick()
                func(unpack(args))
            end
        end)
    end
end

function Utils:Throttle(func, limit, interval)
    local calls = 0
    local lastReset = tick()
    
    return function(...)
        local now = tick()
        
        if now - lastReset >= interval then
            calls = 0
            lastReset = now
        end
        
        if calls < limit then
            calls = calls + 1
            return func(...)
        end
        
        return nil
    end
end

function Utils:CreateInstance(className, properties, children)
    local instance = Instance.new(className)
    
    if properties then
        for prop, value in pairs(properties) do
            if pcall(function()
                instance[prop] = value
            end) then
                -- Propriedade definida com sucesso
            else
                self:Warning(string.format("Failed to set property %s on %s", prop, className), "Utils")
            end
        end
    end
    
    if children then
        for _, child in ipairs(children) do
            if type(child) == "table" and child.ClassName then
                child.Parent = instance
            end
        end
    end
    
    return instance
end

function Utils:DestroyInstance(instance)
    if instance and instance:IsA("Instance") then
        instance:Destroy()
        return true
    end
    return false
end

function Utils:WaitForChild(parent, childName, timeout)
    timeout = timeout or 10
    local startTime = tick()
    
    while tick() - startTime < timeout do
        local child = parent:FindFirstChild(childName)
        if child then
            return child
        end
        wait(0.1)
    end
    
    return nil
end

function Utils:WaitForProperty(instance, propertyName, timeout)
    timeout = timeout or 10
    local startTime = tick()
    
    while tick() - startTime < timeout do
        local success, value = pcall(function()
            return instance[propertyName]
        end)
        
        if success and value ~= nil then
            return value
        end
        
        wait(0.1)
    end
    
    return nil
end

function Utils:GetPlayerByName(name)
    name = name:lower()
    
    for _, player in ipairs(game.Players:GetPlayers()) do
        if player.Name:lower():find(name, 1, true) then
            return player
        end
    end
    
    return nil
end

function Utils:GetPlayerByUserId(userId)
    for _, player in ipairs(game.Players:GetPlayers()) do
        if player.UserId == userId then
            return player
        end
    end
    
    return nil
end

function Utils:GetPlayersInRadius(position, radius)
    local players = {}
    
    for _, player in ipairs(game.Players:GetPlayers()) do
        local character = player.Character
        if character then
            local rootPart = character:FindFirstChild("HumanoidRootPart")
            if rootPart and (rootPart.Position - position).Magnitude <= radius then
                table.insert(players, player)
            end
        end
    end
    
    return players
end

function Utils:GetClosestPlayer(position)
    local closestPlayer = nil
    local closestDistance = math.huge
    
    for _, player in ipairs(game.Players:GetPlayers()) do
        if player ~= game.Players.LocalPlayer then
            local character = player.Character
            if character then
                local rootPart = character:FindFirstChild("HumanoidRootPart")
                if rootPart then
                    local distance = (rootPart.Position - position).Magnitude
                    if distance < closestDistance then
                        closestDistance = distance
                        closestPlayer = player
                    end
                end
            end
        end
    end
    
    return closestPlayer, closestDistance
end

function Utils:GetCharacter(player)
    player = player or game.Players.LocalPlayer
    return player.Character or player.CharacterAdded:Wait()
end

function Utils:GetHumanoid(player)
    local character = self:GetCharacter(player)
    return character:FindFirstChildOfClass("Humanoid")
end

function Utils:GetRootPart(player)
    local character = self:GetCharacter(player)
    return character:FindFirstChild("HumanoidRootPart") or character:FindFirstChild("Torso")
end

function Utils:IsAlive(player)
    local character = self:GetCharacter(player)
    local humanoid = character:FindFirstChildOfClass("Humanoid")
    return humanoid and humanoid.Health > 0
end

function Utils:GetTool(player)
    local character = self:GetCharacter(player)
    if not character then return nil end
    
    for _, tool in ipairs(character:GetChildren()) do
        if tool:IsA("Tool") then
            return tool
        end
    end
    
    return nil
end

-- ============================================================================
-- SEÇÃO 14: FUNÇÕES DE CONVERSÃO
-- ============================================================================

function Utils:ToVector3(value)
    if type(value) == "Vector3" then
        return value
    elseif type(value) == "CFrame" then
        return value.Position
    elseif type(value) == "table" and #value >= 3 then
        return Vector3.new(value[1] or 0, value[2] or 0, value[3] or 0)
    else
        return Vector3.new(0, 0, 0)
    end
end

function Utils:ToCFrame(value)
    if type(value) == "CFrame" then
        return value
    elseif type(value) == "Vector3" then
        return CFrame.new(value)
    elseif type(value) == "table" and #value >= 3 then
        return CFrame.new(value[1] or 0, value[2] or 0, value[3] or 0)
    else
        return CFrame.new()
    end
end

function Utils:ToColor3(value)
    if type(value) == "Color3" then
        return value
    elseif type(value) == "string" then
        -- Converter hex para Color3
        value = value:gsub("#", "")
        if #value == 6 then
            local r = tonumber("0x" .. value:sub(1, 2)) / 255
            local g = tonumber("0x" .. value:sub(3, 4)) / 255
            local b = tonumber("0x" .. value:sub(5, 6)) / 255
            return Color3.new(r, g, b)
        end
    elseif type(value) == "table" and #value >= 3 then
        return Color3.new(value[1] or 0, value[2] or 0, value[3] or 0)
    end
    
    return Color3.new(1, 1, 1)
end

function Utils:ToNumber(value, defaultValue)
    defaultValue = defaultValue or 0
    
    if type(value) == "number" then
        return value
    elseif type(value) == "string" then
        local num = tonumber(value)
        return num or defaultValue
    elseif type(value) == "boolean" then
        return value and 1 or 0
    else
        return defaultValue
    end
end

function Utils:ToString(value, defaultValue)
    defaultValue = defaultValue or ""
    
    if type(value) == "string" then
        return value
    elseif type(value) == "number" then
        return tostring(value)
    elseif type(value) == "boolean" then
        return value and "true" or "false"
    elseif type(value) == "nil" then
        return "nil"
    else
        return defaultValue
    end
end

function Utils:ToBoolean(value)
    if type(value) == "boolean" then
        return value
    elseif type(value) == "string" then
        local lower = value:lower()
        return lower == "true" or lower == "yes" or lower == "1" or lower == "on"
    elseif type(value) == "number" then
        return value ~= 0
    else
        return false
    end
end

-- ============================================================================
-- SEÇÃO 15: FUNÇÕES DE DEBUG E DESENVOLVIMENTO
-- ============================================================================

function Utils:Dump(value, label, maxDepth)
    label = label or "DUMP"
    maxDepth = maxDepth or 5
    
    local output = "\n" .. string.rep("=", 50) .. "\n"
    output = output .. "[" .. label .. "]\n"
    output = output .. string.rep("=", 50) .. "\n"
    output = output .. self:Serialize(value, {prettyPrint = true, maxDepth = maxDepth})
    output = output .. "\n" .. string.rep("=", 50) .. "\n"
    
    print(output)
    return output
end

function Utils:Inspect(value, label)
    label = label or "INSPECT"
    
    local output = "\n" .. string.rep("-", 60) .. "\n"
    output = output .. "[" .. label .. "]\n"
    output = output .. string.rep("-", 60) .. "\n"
    
    local function inspectImpl(val, depth, path)
        depth = depth or 0
        path = path or ""
        
        if depth > 5 then
            output = output .. string.rep("  ", depth) .. path .. ": ... (max depth)\n"
            return
        end
        
        local t = type(val)
        
        if t == "table" then
            output = output .. string.rep("  ", depth) .. path .. ": table\n"
            
            for k, v in pairs(val) do
                local keyPath = path == "" and tostring(k) or path .. "." .. tostring(k)
                inspectImpl(v, depth + 1, keyPath)
            end
        elseif t == "function" then
            output = output .. string.rep("  ", depth) .. path .. ": function\n"
        elseif t == "userdata" then
            output = output .. string.rep("  ", depth) .. path .. ": userdata\n"
        elseif t == "thread" then
            output = output .. string.rep("  ", depth) .. path .. ": thread\n"
        else
            output = output .. string.rep("  ", depth) .. path .. ": " .. tostring(val) .. " (" .. t .. ")\n"
        end
    end
    
    inspectImpl(value)
    output = output .. string.rep("-", 60) .. "\n"
    
    print(output)
    return output
end

function Utils:BenchmarkMemory(label)
    local startMemory = self:GetMemoryUsage()
    
    return function()
        local endMemory = self:GetMemoryUsage()
        local diff = endMemory - startMemory
        
        self:Info(string.format("%s: Memory Δ = %.2f KB", label, diff), "Benchmark")
        return diff
    end
end

function Utils:Trace(label)
    local trace = debug.traceback()
    
    if label then
        self:Info(label .. ":\n" .. trace, "Trace")
    else
        self:Info("Trace:\n" .. trace, "Trace")
    end
    
    return trace
end

function Utils:GetCallerInfo(level)
    level = (level or 1) + 1
    
    local info = debug.getinfo(level, "nlS")
    if not info then return "Unknown" end
    
    return string.format("%s:%d", info.short_src, info.currentline)
end

-- ============================================================================
-- SEÇÃO 16: INICIALIZAÇÃO E CONFIGURAÇÃO
-- ============================================================================

function Utils:Initialize(config)
    -- Configurar logging
    if config and config.logging then
        for key, value in pairs(config.logging) do
            if self.LogConfig[key] ~= nil then
                self.LogConfig[key] = value
            end
        end
    end
    
    -- Configurar cache
    if config and config.cache then
        for key, value in pairs(config.cache) do
            if self.Cache.config[key] ~= nil then
                self.Cache.config[key] = value
            end
        end
    end
    
    -- Configurar performance
    if config and config.performance then
        for key, value in pairs(config.performance) do
            if self.Performance.config[key] ~= nil then
                self.Performance.config[key] = value
            end
        end
    end
    
    -- Inicializar sistemas
    self:CacheInit()
    
    self:Info("Utils inicializado com sucesso", "Utils")
    self:Info("Versão: " .. self.Constants.VERSION, "Utils")
    self:Info("Build: " .. self.Constants.BUILD_DATE, "Utils")
    
    return self
end

function Utils:Shutdown()
    self:CacheStopCleanup()
    self:DisconnectAllSignals()
    
    -- Parar todos os monitores de performance
    for name in pairs(self.Performance.monitors) do
        self:StopPerformanceMonitor(name)
    end
    
    self:Info("Utils desligado", "Utils")
    return true
end

function Utils:GetVersion()
    return self.Constants.VERSION
end

function Utils:GetStats()
    return {
        logging = {
            enabled = self.LogConfig.enabled,
            historySize = #self.LogHistory,
            logFile = self.LogConfig.logToFile
        },
        cache = self:CacheGetStats(),
        performance = {
            enabled = self.Performance.config.enabled,
            monitorCount = self:TableSize(self.Performance.monitors),
            benchmarkCount = self:TableSize(self.Performance.benchmarks)
        },
        signals = {
            activeCount = #self.Signals,
            totalListeners = 0
        }
    }
end

-- Exportar funções globais para conveniência
_G.NexusUtils = Utils

return Utils
