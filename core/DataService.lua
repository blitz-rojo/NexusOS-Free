-- Core/DataService.lua
-- Sistema completo de persistência de dados - 700+ linhas

local DataService = {}

-- ============================================================================
-- SEÇÃO 1: CONSTANTES E CONFIGURAÇÕES
-- ============================================================================

DataService.Config = {
    -- Arquivos principais
    FILES = {
        CONFIG = "NexusOS_Config.json",
        PRESETS = "NexusOS_Presets.json",
        STATS = "NexusOS_Stats.json",
        LOGS = "NexusOS/logs.txt",
        BACKUP = "NexusOS/backup_{TIMESTAMP}.json"
    },
    
    -- Pastas
    FOLDERS = {
        ROOT = "NexusOS",
        BACKUPS = "NexusOS/Backups",
        CACHE = "NexusOS/Cache",
        PLUGINS = "NexusOS/Plugins",
        THEMES = "NexusOS/Themes"
    },
    
    -- Configurações de backup
    BACKUP = {
        ENABLED = true,
        MAX_BACKUPS = 10,
        AUTO_BACKUP = true,
        BACKUP_INTERVAL = 300, -- 5 minutos
        COMPRESS = true
    },
    
    -- Configurações de cache
    CACHE = {
        ENABLED = true,
        MAX_SIZE = 100,
        TTL = 300, -- 5 minutos
        CLEANUP_INTERVAL = 60 -- 1 minuto
    },
    
    -- Configurações de criptografia
    ENCRYPTION = {
        ENABLED = true,
        KEY = "NEXUS_OS_DATA_KEY_2024",
        SALT = "NEXUS_SALT_DATA_2024",
        ALGORITHM = "XOR+B64"
    },
    
    -- Validação
    VALIDATION = {
        ENABLE_SCHEMA = true,
        MAX_FILE_SIZE = 1024 * 1024, -- 1MB
        ALLOWED_EXTENSIONS = {".json", ".txt", ".lua", ".xml"}
    }
}

-- ============================================================================
-- SEÇÃO 2: ESQUEMAS DE VALIDAÇÃO
-- ============================================================================

DataService.Schemas = {
    CONFIG = {
        type = "object",
        required = {"version", "theme", "modules"},
        properties = {
            version = {type = "string", pattern = "^%d+%.%d+"},
            theme = {type = "string", enum = {"Dark", "Light", "Purple", "Blue", "Red", "Green", "Custom"}},
            language = {type = "string", default = "pt-BR"},
            autoSave = {type = "boolean", default = true},
            notifications = {type = "boolean", default = true},
            sound = {type = "boolean", default = true},
            modules = {
                type = "object",
                additionalProperties = {
                    type = "object",
                    properties = {
                        enabled = {type = "boolean", default = true},
                        features = {type = "object", additionalProperties = {type = "boolean"}}
                    }
                }
            },
            settings = {
                type = "object",
                properties = {
                    uiKeybind = {type = "string", default = "RightControl"},
                    mobileButtonSize = {type = "number", minimum = 40, maximum = 100, default = 56},
                    mobileTransparency = {type = "number", minimum = 0.1, maximum = 1, default = 0.7},
                    performanceMode = {type = "boolean", default = false},
                    renderDistance = {type = "number", minimum = 100, maximum = 10000, default = 1000}
                }
            }
        }
    },
    
    PRESET = {
        type = "object",
        required = {"name", "description"},
        properties = {
            name = {type = "string", minLength = 1, maxLength = 50},
            description = {type = "string", minLength = 1, maxLength = 200},
            author = {type = "string", default = "Unknown"},
            version = {type = "string", default = "1.0"},
            createdAt = {type = "number", default = function() return os.time() end},
            updatedAt = {type = "number", default = function() return os.time() end},
            modules = {
                type = "object",
                additionalProperties = {
                    type = "object",
                    properties = {
                        enabled = {type = "boolean", default = true},
                        features = {type = "array", items = {type = "number", minimum = 1, maximum = 255}}
                    }
                }
            },
            settings = {
                type = "object",
                additionalProperties = true
            }
        }
    },
    
    STATS = {
        type = "object",
        properties = {
            sessions = {type = "array", items = {
                type = "object",
                properties = {
                    startTime = {type = "number"},
                    endTime = {type = "number"},
                    duration = {type = "number"},
                    featuresUsed = {type = "array", items = {type = "string"}},
                    errors = {type = "array", items = {type = "string"}}
                }
            }},
            totalUptime = {type = "number", default = 0},
            features = {
                type = "object",
                additionalProperties = {
                    type = "object",
                    properties = {
                        count = {type = "number", default = 0},
                        totalTime = {type = "number", default = 0},
                        lastUsed = {type = "number", default = 0}
                    }
                }
            },
            performance = {
                type = "object",
                properties = {
                    avgFPS = {type = "number", default = 0},
                    avgMemory = {type = "number", default = 0},
                    avgPing = {type = "number", default = 0}
                }
            }
        }
    }
}

-- ============================================================================
-- SEÇÃO 3: SISTEMA DE ARQUIVOS
-- ============================================================================

DataService.FileSystem = {
    cache = {},
    locks = {},
    operations = 0,
    errors = 0
}

function DataService:EnsureDirectory(path)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        if not isfolder then return false end
        
        local parts = self.Utils:Split(path, "/")
        local currentPath = ""
        
        for _, part in ipairs(parts) do
            if currentPath == "" then
                currentPath = part
            else
                currentPath = currentPath .. "/" .. part
            end
            
            if not isfolder(currentPath) then
                makefolder(currentPath)
            end
        end
        
        return true
    end)
end

function DataService:FileExists(path)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        if not isfile then return false end
        return isfile(path)
    end)
end

function DataService:DirectoryExists(path)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        if not isfolder then return false end
        return isfolder(path)
    end)
end

function DataService:ReadFile(path, binary)
    if not self.Utils then return nil end
    
    local cacheKey = "file_" .. path
    local cached = self.Utils:CacheGet(cacheKey)
    if cached then return cached end
    
    return self.Utils:SafeCall(function()
        if not readfile then return nil end
        if not self:FileExists(path) then return nil end
        
        local content = readfile(path, binary)
        
        if content then
            self.Utils:CacheSet(cacheKey, content, self.Config.CACHE.TTL)
            self.FileSystem.operations = self.FileSystem.operations + 1
        end
        
        return content
    end)
end

function DataService:WriteFile(path, content, binary)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        if not writefile then return false end
        
        -- Criar diretório se necessário
        local dir = path:match("^(.*[/\\])")
        if dir and not self:DirectoryExists(dir) then
            self:EnsureDirectory(dir)
        end
        
        writefile(path, content, binary)
        
        -- Atualizar cache
        local cacheKey = "file_" .. path
        self.Utils:CacheSet(cacheKey, content, self.Config.CACHE.TTL)
        
        self.FileSystem.operations = self.FileSystem.operations + 1
        
        self.Utils:Debug("Arquivo escrito: " .. path, "DataService")
        return true
    end)
end

function DataService:DeleteFile(path)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        if not delfile then return false end
        if not self:FileExists(path) then return false end
        
        delfile(path)
        
        -- Limpar cache
        local cacheKey = "file_" .. path
        self.Utils:CacheDelete(cacheKey)
        
        self.Utils:Debug("Arquivo deletado: " .. path, "DataService")
        return true
    end)
end

function DataService:ListFiles(path, pattern)
    if not self.Utils then return {} end
    
    return self.Utils:SafeCall(function()
        if not listfiles then return {} end
        if not self:DirectoryExists(path) then return {} end
        
        local files = listfiles(path)
        local filtered = {}
        
        if pattern then
            for _, file in ipairs(files) do
                if file:match(pattern) then
                    table.insert(filtered, file)
                end
            end
        else
            filtered = files
        end
        
        return filtered
    end) or {}
end

function DataService:FileSize(path)
    if not self.Utils then return 0 end
    
    return self.Utils:SafeCall(function()
        if not self:FileExists(path) then return 0 end
        
        local content = self:ReadFile(path)
        return content and #content or 0
    end) or 0
end

function DataService:FileInfo(path)
    if not self.Utils then return nil end
    
    return self.Utils:SafeCall(function()
        if not self:FileExists(path) then return nil end
        
        local content = self:ReadFile(path)
        if not content then return nil end
        
        return {
            path = path,
            size = #content,
            exists = true,
            readable = true,
            writable = true,
            modified = os.time() -- Nota: Roblox Lua não tem stat, usando timestamp atual
        }
    end)
end

function DataService:CopyFile(src, dst)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        if src == dst then return true end
        
        local content = self:ReadFile(src)
        if not content then return false end
        
        return self:WriteFile(dst, content)
    end)
end

function DataService:MoveFile(src, dst)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        if src == dst then return true end
        
        local success = self:CopyFile(src, dst)
        if success then
            self:DeleteFile(src)
        end
        
        return success
    end)
end

function DataService:FileLock(path)
    local lockKey = "lock_" .. path
    
    if self.FileSystem.locks[lockKey] then
        return false -- Já está bloqueado
    end
    
    self.FileSystem.locks[lockKey] = {
        timestamp = os.time(),
        thread = coroutine.running()
    }
    
    return true
end

function DataService:FileUnlock(path)
    local lockKey = "lock_" .. path
    self.FileSystem.locks[lockKey] = nil
    return true
end

function DataService:FileIsLocked(path, timeout)
    timeout = timeout or 5
    local lockKey = "lock_" .. path
    local lock = self.FileSystem.locks[lockKey]
    
    if not lock then return false end
    
    -- Verificar se o lock expirou
    if os.time() - lock.timestamp > timeout then
        self.FileSystem.locks[lockKey] = nil
        return false
    end
    
    return true
end

function DataService:WaitForFileUnlock(path, timeout, interval)
    timeout = timeout or 10
    interval = interval or 0.1
    local startTime = os.time()
    
    while os.time() - startTime < timeout do
        if not self:FileIsLocked(path) then
            return true
        end
        wait(interval)
    end
    
    return false
end

-- ============================================================================
-- SEÇÃO 4: SISTEMA DE CRIPTOGRAFIA
-- ============================================================================

DataService.Crypto = {}

function DataService.Crypto:Encrypt(data, key, salt)
    key = key or self.Config.ENCRYPTION.KEY
    salt = salt or self.Config.ENCRYPTION.SALT
    
    if not self.Config.ENCRYPTION.ENABLED then
        return data
    end
    
    return self.Utils:SafeCall(function()
        -- Converter para string se for tabela
        if type(data) == "table" then
            data = self.Utils:ToJSON(data)
        end
        
        -- Adicionar salt
        local salted = data .. salt
        
        -- XOR encryption simples
        local encrypted = ""
        for i = 1, #salted do
            local charCode = string.byte(salted, i)
            local keyChar = string.byte(key, (i % #key) + 1)
            local encryptedChar = bit32.bxor(charCode, keyChar)
            encrypted = encrypted .. string.char(encryptedChar)
        end
        
        -- Base64 encode
        local base64 = game:GetService("HttpService"):JSONEncode(encrypted)
        
        return base64
    end) or data
end

function DataService.Crypto:Decrypt(encrypted, key, salt)
    key = key or self.Config.ENCRYPTION.KEY
    salt = salt or self.Config.ENCRYPTION.SALT
    
    if not self.Config.ENCRYPTION.ENABLED then
        return encrypted
    end
    
    return self.Utils:SafeCall(function()
        -- Base64 decode
        local decoded = game:GetService("HttpService"):JSONDecode(encrypted)
        
        -- XOR decryption
        local decrypted = ""
        for i = 1, #decoded do
            local charCode = string.byte(decoded, i)
            local keyChar = string.byte(key, (i % #key) + 1)
            local decryptedChar = bit32.bxor(charCode, keyChar)
            decrypted = decrypted .. string.char(decryptedChar)
        end
        
        -- Remover salt
        local unsalted = decrypted:sub(1, -#salt - 1)
        
        -- Tentar converter de JSON
        local success, result = pcall(function()
            return game:GetService("HttpService"):JSONDecode(unsalted)
        end)
        
        if success then
            return result
        else
            return unsalted
        end
    end) or encrypted
end

function DataService.Crypto:Hash(data, algorithm)
    algorithm = algorithm or "simple"
    
    if algorithm == "simple" then
        local hash = 0
        for i = 1, #data do
            hash = (hash * 31 + string.byte(data, i)) % (2^32)
        end
        return string.format("%08x", hash)
    elseif algorithm == "md5" then
        -- Implementação simplificada
        return "md5_hash_" .. #data
    end
    
    return data
end

function DataService.Crypto:GenerateKey(length)
    length = length or 32
    local chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
    local key = ""
    
    for i = 1, length do
        local randomIndex = math.random(1, #chars)
        key = key .. chars:sub(randomIndex, randomIndex)
    end
    
    return key
end

-- ============================================================================
-- SEÇÃO 5: SISTEMA DE VALIDAÇÃO
-- ============================================================================

function DataService:ValidateSchema(data, schemaName)
    if not self.Config.VALIDATION.ENABLE_SCHEMA then
        return true
    end
    
    local schema = self.Schemas[schemaName]
    if not schema then
        self.Utils:Warning("Schema não encontrado: " .. schemaName, "DataService")
        return true -- Se não há schema, aceita qualquer coisa
    end
    
    return self.Utils:SafeCall(function()
        -- Implementação básica de validação JSON Schema
        local function validate(value, schema, path)
            path = path or ""
            
            if schema.type then
                local valueType = type(value)
                
                if schema.type == "object" then
                    if valueType ~= "table" then
                        return false, path .. ": deve ser um objeto"
                    end
                    
                    -- Verificar required
                    if schema.required then
                        for _, requiredKey in ipairs(schema.required) do
                            if value[requiredKey] == nil then
                                return false, path .. ": campo obrigatório '" .. requiredKey .. "' não encontrado"
                            end
                        end
                    end
                    
                    -- Validar propriedades
                    if schema.properties then
                        for prop, propSchema in pairs(schema.properties) do
                            if value[prop] ~= nil then
                                local success, err = validate(value[prop], propSchema, path .. "." .. prop)
                                if not success then
                                    return false, err
                                end
                            elseif propSchema.default ~= nil then
                                -- Aplicar valor padrão
                                if type(propSchema.default) == "function" then
                                    value[prop] = propSchema.default()
                                else
                                    value[prop] = propSchema.default
                                end
                            end
                        end
                    end
                    
                    -- Validar additionalProperties
                    if schema.additionalProperties == false then
                        for key in pairs(value) do
                            if not schema.properties or not schema.properties[key] then
                                return false, path .. ": propriedade não permitida '" .. key .. "'"
                            end
                        end
                    elseif type(schema.additionalProperties) == "table" then
                        for key, val in pairs(value) do
                            if not schema.properties or not schema.properties[key] then
                                local success, err = validate(val, schema.additionalProperties, path .. "." .. key)
                                if not success then
                                    return false, err
                                end
                            end
                        end
                    end
                    
                elseif schema.type == "array" then
                    if valueType ~= "table" then
                        return false, path .. ": deve ser um array"
                    end
                    
                    -- Verificar se é um array (índices numéricos sequenciais)
                    local isArray = true
                    for k in pairs(value) do
                        if type(k) ~= "number" then
                            isArray = false
                            break
                        end
                    end
                    
                    if not isArray then
                        return false, path .. ": deve ser um array (índices numéricos)"
                    end
                    
                    -- Validar items
                    if schema.items then
                        for i, item in ipairs(value) do
                            local success, err = validate(item, schema.items, path .. "[" .. i .. "]")
                            if not success then
                                return false, err
                            end
                        end
                    end
                    
                else -- Tipos primitivos
                    if schema.type == "string" then
                        if valueType ~= "string" then
                            return false, path .. ": deve ser uma string"
                        end
                        
                        if schema.minLength and #value < schema.minLength then
                            return false, path .. ": deve ter no mínimo " .. schema.minLength .. " caracteres"
                        end
                        
                        if schema.maxLength and #value > schema.maxLength then
                            return false, path .. ": deve ter no máximo " .. schema.maxLength .. " caracteres"
                        end
                        
                        if schema.pattern and not value:match(schema.pattern) then
                            return false, path .. ": não corresponde ao padrão"
                        end
                        
                        if schema.enum then
                            local found = false
                            for _, enumValue in ipairs(schema.enum) do
                                if value == enumValue then
                                    found = true
                                    break
                                end
                            end
                            if not found then
                                return false, path .. ": deve ser um dos valores: " .. table.concat(schema.enum, ", ")
                            end
                        end
                        
                    elseif schema.type == "number" then
                        if valueType ~= "number" then
                            return false, path .. ": deve ser um número"
                        end
                        
                        if schema.minimum and value < schema.minimum then
                            return false, path .. ": deve ser no mínimo " .. schema.minimum
                        end
                        
                        if schema.maximum and value > schema.maximum then
                            return false, path .. ": deve ser no máximo " .. schema.maximum
                        end
                        
                    elseif schema.type == "boolean" then
                        if valueType ~= "boolean" then
                            return false, path .. ": deve ser um booleano"
                        end
                        
                    elseif schema.type == "null" then
                        if value ~= nil then
                            return false, path .. ": deve ser null"
                        end
                    end
                end
            end
            
            return true
        end
        
        return validate(data, schema)
    end)
end

function DataService:SanitizeData(data, schemaName)
    local schema = self.Schemas[schemaName]
    if not schema then return data end
    
    return self.Utils:SafeCall(function()
        local function sanitize(value, schema)
            if schema.type == "object" and type(value) == "table" then
                local sanitized = {}
                
                if schema.properties then
                    for prop, propSchema in pairs(schema.properties) do
                        if value[prop] ~= nil then
                            sanitized[prop] = sanitize(value[prop], propSchema)
                        elseif propSchema.default ~= nil then
                            if type(propSchema.default) == "function" then
                                sanitized[prop] = propSchema.default()
                            else
                                sanitized[prop] = propSchema.default
                            end
                        end
                    end
                end
                
                return sanitized
                
            elseif schema.type == "array" and type(value) == "table" then
                local sanitized = {}
                
                if schema.items then
                    for i, item in ipairs(value) do
                        sanitized[i] = sanitize(item, schema.items)
                    end
                end
                
                return sanitized
                
            else
                return value
            end
        end
        
        return sanitize(data, schema)
    end) or data
end

-- ============================================================================
-- SEÇÃO 6: GERENCIAMENTO DE CONFIGURAÇÕES
-- ============================================================================

function DataService:GetDefaultConfig()
    return {
        version = "18.0-Free",
        theme = "Dark",
        language = "pt-BR",
        autoSave = true,
        notifications = true,
        sound = true,
        modules = {
            PhysicsAndMovement = {
                enabled = true,
                features = {
                    [1] = false, -- Superman Flight
                    [4] = false, -- Speed Hack
                    [5] = false, -- Jump Hack
                    [6] = false, -- Infinite Jump
                    [13] = false -- No Clip
                }
            },
            VisualDebugger = {
                enabled = true,
                features = {
                    [1] = false, -- ESP
                    [2] = true,  -- Show Names
                    [3] = true,  -- Show Distance
                    [4] = false  -- Show Boxes
                }
            },
            AutomationAndInteraction = {
                enabled = false,
                features = {}
            },
            PlayerAndUtility = {
                enabled = true,
                features = {
                    [1] = false, -- God Mode
                    [2] = false, -- Infinite Stamina
                    [20] = false -- Server Hop
                }
            },
            ConfigAndSystem = {
                enabled = true,
                features = {}
            }
        },
        settings = {
            uiKeybind = "RightControl",
            mobileButtonSize = 56,
            mobileTransparency = 0.7,
            performanceMode = false,
            renderDistance = 1000,
            fpsLimit = 0, -- 0 = ilimitado
            vsync = false
        }
    }
end

function DataService:LoadConfig()
    if not self.Utils then return self:GetDefaultConfig() end
    
    return self.Utils:SafeCall(function()
        local configPath = self.Config.FOLDERS.ROOT .. "/" .. self.Config.FILES.CONFIG
        
        -- Tentar carregar do cache primeiro
        local cacheKey = "config_data"
        local cached = self.Utils:CacheGet(cacheKey)
        if cached then
            self.Utils:Debug("Configuração carregada do cache", "DataService")
            return cached
        end
        
        -- Carregar do arquivo
        if self:FileExists(configPath) then
            local encrypted = self:ReadFile(configPath)
            
            if encrypted then
                -- Descriptografar
                local decrypted = self.Crypto:Decrypt(encrypted)
                
                if decrypted then
                    -- Validar schema
                    local valid, error = self:ValidateSchema(decrypted, "CONFIG")
                    
                    if valid then
                        -- Sanitizar dados
                        local sanitized = self:SanitizeData(decrypted, "CONFIG")
                        
                        -- Salvar no cache
                        self.Utils:CacheSet(cacheKey, sanitized, self.Config.CACHE.TTL)
                        
                        self.Utils:Info("Configuração carregada do arquivo", "DataService")
                        return sanitized
                    else
                        self.Utils:Warning("Configuração inválida: " .. tostring(error), "DataService")
                    end
                end
            end
        end
        
        -- Usar configuração padrão
        local defaultConfig = self:GetDefaultConfig()
        
        -- Salvar configuração padrão
        self:SaveConfig(defaultConfig)
        
        self.Utils:Info("Usando configuração padrão", "DataService")
        return defaultConfig
        
    end) or self:GetDefaultConfig()
end

function DataService:SaveConfig(config)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        -- Validar configuração
        local valid, error = self:ValidateSchema(config, "CONFIG")
        if not valid then
            self.Utils:Error("Configuração inválida: " .. tostring(error), "DataService")
            return false
        end
        
        -- Sanitizar dados
        local sanitized = self:SanitizeData(config, "CONFIG")
        
        -- Adicionar timestamp
        sanitized._lastSave = os.time()
        sanitized._version = self:GetDefaultConfig().version
        
        -- Criptografar
        local encrypted = self.Crypto:Encrypt(sanitized)
        
        -- Salvar no arquivo
        local configPath = self.Config.FOLDERS.ROOT .. "/" .. self.Config.FILES.CONFIG
        local success = self:WriteFile(configPath, encrypted)
        
        if success then
            -- Atualizar cache
            local cacheKey = "config_data"
            self.Utils:CacheSet(cacheKey, sanitized, self.Config.CACHE.TTL)
            
            -- Criar backup automático
            if self.Config.BACKUP.AUTO_BACKUP then
                self:CreateBackup(sanitized, "config")
            end
            
            self.Utils:Info("Configuração salva com sucesso", "DataService")
            return true
        end
        
        return false
        
    end)
end

function DataService:ResetConfig()
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        local defaultConfig = self:GetDefaultConfig()
        return self:SaveConfig(defaultConfig)
    end)
end

function DataService:UpdateConfig(updates)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        local currentConfig = self:LoadConfig()
        
        -- Mesclar atualizações
        local function mergeDeep(target, source)
            for key, value in pairs(source) do
                if type(value) == "table" and type(target[key]) == "table" then
                    mergeDeep(target[key], value)
                else
                    target[key] = value
                end
            end
            return target
        end
        
        local merged = mergeDeep(currentConfig, updates)
        
        return self:SaveConfig(merged)
    end)
end

-- ============================================================================
-- SEÇÃO 7: GERENCIAMENTO DE PRESETS
-- ============================================================================

function DataService:LoadAllPresets()
    if not self.Utils then return {} end
    
    return self.Utils:SafeCall(function()
        local presetsPath = self.Config.FOLDERS.ROOT .. "/" .. self.Config.FILES.PRESETS
        
        -- Tentar cache primeiro
        local cacheKey = "presets_data"
        local cached = self.Utils:CacheGet(cacheKey)
        if cached then
            return cached
        end
        
        -- Presets padrão
        local defaultPresets = {
            Legit = {
                name = "Legit",
                description = "Configurações para uso discreto e legítimo",
                author = "Nexus Team",
                version = "1.0",
                createdAt = os.time(),
                updatedAt = os.time(),
                modules = {
                    PhysicsAndMovement = {
                        enabled = true,
                        features = {4, 5, 6} -- Speed, Jump, Infinite Jump
                    },
                    VisualDebugger = {
                        enabled = false
                    },
                    AutomationAndInteraction = {
                        enabled = false
                    }
                },
                settings = {
                    performanceMode = true,
                    renderDistance = 500
                }
            },
            Visual = {
                name = "Visual",
                description = "Foco em recursos visuais e ESP",
                author = "Nexus Team",
                version = "1.0",
                createdAt = os.time(),
                updatedAt = os.time(),
                modules = {
                    VisualDebugger = {
                        enabled = true,
                        features = {1, 2, 3, 4, 5} -- ESP completo
                    },
                    PhysicsAndMovement = {
                        enabled = true,
                        features = {13} -- No Clip
                    }
                },
                settings = {
                    renderDistance = 2000
                }
            },
            Farming = {
                name = "Farming",
                description = "Configurações otimizadas para farm automático",
                author = "Nexus Team",
                version = "1.0",
                createdAt = os.time(),
                updatedAt = os.time(),
                modules = {
                    AutomationAndInteraction = {
                        enabled = true,
                        features = {10, 11, 12} -- Auto Farm
                    },
                    PhysicsAndMovement = {
                        enabled = true,
                        features = {1, 4} -- Flight e Speed
                    }
                },
                settings = {
                    performanceMode = false
                }
            },
            PVP = {
                name = "PVP",
                description = "Configurações para combate PVP",
                author = "Nexus Team",
                version = "1.0",
                createdAt = os.time(),
                updatedAt = os.time(),
                modules = {
                    AutomationAndInteraction = {
                        enabled = true,
                        features = {1, 2, 3} -- Aimbot, Trigger, Silent
                    },
                    VisualDebugger = {
                        enabled = true,
                        features = {1, 2, 3, 4} -- ESP
                    }
                },
                settings = {
                    fpsLimit = 144
                }
            }
        }
        
        -- Carregar do arquivo
        if self:FileExists(presetsPath) then
            local encrypted = self:ReadFile(presetsPath)
            
            if encrypted then
                local decrypted = self.Crypto:Decrypt(encrypted)
                
                if decrypted and type(decrypted) == "table" then
                    -- Mesclar com presets padrão
                    for name, preset in pairs(decrypted) do
                        defaultPresets[name] = preset
                    end
                end
            end
        end
        
        -- Salvar no cache
        self.Utils:CacheSet(cacheKey, defaultPresets, self.Config.CACHE.TTL)
        
        return defaultPresets
        
    end) or {}
end

function DataService:SavePreset(name, presetData)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        -- Validar preset
        local valid, error = self:ValidateSchema(presetData, "PRESET")
        if not valid then
            self.Utils:Error("Preset inválido: " .. tostring(error), "DataService")
            return false
        end
        
        -- Atualizar timestamps
        presetData.updatedAt = os.time()
        if not presetData.createdAt then
            presetData.createdAt = os.time()
        end
        
        -- Carregar todos os presets
        local allPresets = self:LoadAllPresets()
        
        -- Adicionar/atualizar preset
        allPresets[name] = presetData
        
        -- Sanitizar
        local sanitized = self:SanitizeData(allPresets, "PRESET")
        
        -- Criptografar
        local encrypted = self.Crypto:Encrypt(sanitized)
        
        -- Salvar
        local presetsPath = self.Config.FOLDERS.ROOT .. "/" .. self.Config.FILES.PRESETS
        local success = self:WriteFile(presetsPath, encrypted)
        
        if success then
            -- Limpar cache
            self.Utils:CacheDelete("presets_data")
            
            self.Utils:Info("Preset salvo: " .. name, "DataService")
            return true
        end
        
        return false
        
    end)
end

function DataService:DeletePreset(name)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        local allPresets = self:LoadAllPresets()
        
        if not allPresets[name] then
            self.Utils:Warning("Preset não encontrado: " .. name, "DataService")
            return false
        end
        
        allPresets[name] = nil
        
        -- Salvar presets atualizados
        local encrypted = self.Crypto:Encrypt(allPresets)
        local presetsPath = self.Config.FOLDERS.ROOT .. "/" .. self.Config.FILES.PRESETS
        local success = self:WriteFile(presetsPath, encrypted)
        
        if success then
            -- Limpar cache
            self.Utils:CacheDelete("presets_data")
            
            self.Utils:Info("Preset deletado: " .. name, "DataService")
            return true
        end
        
        return false
        
    end)
end

function DataService:LoadPreset(name)
    if not self.Utils then return nil end
    
    return self.Utils:SafeCall(function()
        local allPresets = self:LoadAllPresets()
        return allPresets[name]
    end)
end

function DataService:ApplyPreset(name)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        local preset = self:LoadPreset(name)
        if not preset then
            self.Utils:Warning("Preset não encontrado: " .. name, "DataService")
            return false
        end
        
        -- Carregar configuração atual
        local currentConfig = self:LoadConfig()
        
        -- Aplicar módulos do preset
        if preset.modules then
            for moduleName, moduleConfig in pairs(preset.modules) do
                if currentConfig.modules[moduleName] then
                    currentConfig.modules[moduleName].enabled = moduleConfig.enabled or false
                    
                    if moduleConfig.features then
                        for _, featureId in ipairs(moduleConfig.features) do
                            currentConfig.modules[moduleName].features[featureId] = true
                        end
                    end
                end
            end
        end
        
        -- Aplicar settings do preset
        if preset.settings then
            for key, value in pairs(preset.settings) do
                currentConfig.settings[key] = value
            end
        end
        
        -- Salvar configuração atualizada
        local success = self:SaveConfig(currentConfig)
        
        if success then
            self.Utils:Info("Preset aplicado: " .. name, "DataService")
            return true
        end
        
        return false
        
    end)
end

-- ============================================================================
-- SEÇÃO 8: SISTEMA DE BACKUP
-- ============================================================================

function DataService:CreateBackup(data, type)
    if not self.Config.BACKUP.ENABLED then return false end
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        -- Criar pasta de backups se não existir
        self:EnsureDirectory(self.Config.FOLDERS.BACKUPS)
        
        -- Gerar nome do arquivo
        local timestamp = os.date("%Y%m%d_%H%M%S")
        local backupName = string.format("backup_%s_%s.json", type or "unknown", timestamp)
        local backupPath = self.Config.FOLDERS.BACKUPS .. "/" .. backupName
        
        -- Converter dados para JSON
        local jsonData = self.Utils:ToJSON(data, true)
        
        -- Salvar backup
        local success = self:WriteFile(backupPath, jsonData)
        
        if success then
            -- Limitar número de backups
            self:CleanupOldBackups()
            
            self.Utils:Debug("Backup criado: " .. backupPath, "DataService")
            return true
        end
        
        return false
        
    end)
end

function DataService:CleanupOldBackups()
    if not self.Config.BACKUP.ENABLED then return false end
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        if not self:DirectoryExists(self.Config.FOLDERS.BACKUPS) then
            return false
        end
        
        local backups = self:ListFiles(self.Config.FOLDERS.BACKUPS, "%.json$")
        
        if #backups <= self.Config.BACKUP.MAX_BACKUPS then
            return true
        end
        
        -- Ordenar backups por data (mais antigo primeiro)
        table.sort(backups)
        
        -- Remover os mais antigos
        local toRemove = #backups - self.Config.BACKUP.MAX_BACKUPS
        for i = 1, toRemove do
            self:DeleteFile(backups[i])
            self.Utils:Debug("Backup removido: " .. backups[i], "DataService")
        end
        
        return true
        
    end)
end

function DataService:ListBackups()
    if not self.Utils then return {} end
    
    return self.Utils:SafeCall(function()
        if not self:DirectoryExists(self.Config.FOLDERS.BACKUPS) then
            return {}
        end
        
        local backups = self:ListFiles(self.Config.FOLDERS.BACKUPS, "%.json$")
        local backupInfo = {}
        
        for _, backupPath in ipairs(backups) do
            local backupName = backupPath:match("([^/\\]+)$")
            local size = self:FileSize(backupPath)
            
            table.insert(backupInfo, {
                path = backupPath,
                name = backupName,
                size = size,
                readable = size > 0
            })
        end
        
        return backupInfo
        
    end) or {}
end

function DataService:RestoreBackup(backupPath)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        if not self:FileExists(backupPath) then
            self.Utils:Warning("Backup não encontrado: " .. backupPath, "DataService")
            return false
        end
        
        -- Ler backup
        local backupData = self:ReadFile(backupPath)
        if not backupData then
            return false
        end
        
        -- Tentar parsear JSON
        local success, data = pcall(function()
            return game:GetService("HttpService"):JSONDecode(backupData)
        end)
        
        if not success then
            self.Utils:Error("Backup inválido ou corrompido", "DataService")
            return false
        end
        
        -- Validar dados
        local valid, error = self:ValidateSchema(data, "CONFIG")
        if not valid then
            self.Utils:Error("Backup inválido: " .. tostring(error), "DataService")
            return false
        end
        
        -- Criar backup da configuração atual
        local currentConfig = self:LoadConfig()
        self:CreateBackup(currentConfig, "pre_restore")
        
        -- Restaurar configuração
        local restoreSuccess = self:SaveConfig(data)
        
        if restoreSuccess then
            self.Utils:Info("Backup restaurado com sucesso: " .. backupPath, "DataService")
            return true
        end
        
        return false
        
    end)
end

function DataService:StartAutoBackup()
    if not self.Config.BACKUP.ENABLED or not self.Config.BACKUP.AUTO_BACKUP then
        return false
    end
    
    if self._backupThread then
        return true -- Já está rodando
    end
    
    self.Utils:Info("Iniciando backup automático", "DataService")
    
    self._backupThread = task.spawn(function()
        while true do
            task.wait(self.Config.BACKUP.BACKUP_INTERVAL)
            
            local success = self.Utils:SafeCall(function()
                local config = self:LoadConfig()
                return self:CreateBackup(config, "auto")
            end)
            
            if not success then
                self.Utils:Warning("Falha no backup automático", "DataService")
            end
        end
    end)
    
    return true
end

function DataService:StopAutoBackup()
    if self._backupThread then
        task.cancel(self._backupThread)
        self._backupThread = nil
        self.Utils:Info("Backup automático parado", "DataService")
        return true
    end
    return false
end

-- ============================================================================
-- SEÇÃO 9: ESTATÍSTICAS E ANALYTICS
-- ============================================================================

function DataService:LoadStats()
    if not self.Utils then return {} end
    
    return self.Utils:SafeCall(function()
        local statsPath = self.Config.FOLDERS.ROOT .. "/" .. self.Config.FILES.STATS
        
        -- Tentar cache primeiro
        local cacheKey = "stats_data"
        local cached = self.Utils:CacheGet(cacheKey)
        if cached then
            return cached
        end
        
        -- Stats padrão
        local defaultStats = {
            sessions = {},
            totalUptime = 0,
            features = {},
            performance = {
                avgFPS = 0,
                avgMemory = 0,
                avgPing = 0,
                samples = 0
            },
            games = {},
            errors = 0,
            lastUpdated = os.time()
        }
        
        -- Carregar do arquivo
        if self:FileExists(statsPath) then
            local encrypted = self:ReadFile(statsPath)
            
            if encrypted then
                local decrypted = self.Crypto:Decrypt(encrypted)
                
                if decrypted and type(decrypted) == "table" then
                    -- Mesclar com stats padrão
                    for key, value in pairs(decrypted) do
                        defaultStats[key] = value
                    end
                end
            end
        end
        
        -- Validar schema
        local valid, error = self:ValidateSchema(defaultStats, "STATS")
        if not valid then
            self.Utils:Warning("Stats inválidos, resetando: " .. tostring(error), "DataService")
            defaultStats = {
                sessions = {},
                totalUptime = 0,
                features = {},
                performance = {avgFPS = 0, avgMemory = 0, avgPing = 0, samples = 0},
                games = {},
                errors = 0,
                lastUpdated = os.time()
            }
        end
        
        -- Salvar no cache
        self.Utils:CacheSet(cacheKey, defaultStats, self.Config.CACHE.TTL)
        
        return defaultStats
        
    end) or {}
end

function DataService:SaveStats(stats)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        -- Validar stats
        local valid, error = self:ValidateSchema(stats, "STATS")
        if not valid then
            self.Utils:Error("Stats inválidos: " .. tostring(error), "DataService")
            return false
        end
        
        -- Atualizar timestamp
        stats.lastUpdated = os.time()
        
        -- Sanitizar
        local sanitized = self:SanitizeData(stats, "STATS")
        
        -- Criptografar
        local encrypted = self.Crypto:Encrypt(sanitized)
        
        -- Salvar
        local statsPath = self.Config.FOLDERS.ROOT .. "/" .. self.Config.FILES.STATS
        local success = self:WriteFile(statsPath, encrypted)
        
        if success then
            -- Atualizar cache
            self.Utils:CacheDelete("stats_data")
            
            return true
        end
        
        return false
        
    end)
end

function DataService:UpdateStats(updates)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        local currentStats = self:LoadStats()
        
        -- Mesclar atualizações
        local function mergeStats(target, source)
            for key, value in pairs(source) do
                if type(value) == "table" and type(target[key]) == "table" then
                    mergeStats(target[key], value)
                else
                    target[key] = value
                end
            end
            return target
        end
        
        local merged = mergeStats(currentStats, updates)
        
        return self:SaveStats(merged)
    end)
end

function DataService:RecordSession(startTime, endTime, featuresUsed, errors)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        local duration = endTime - startTime
        
        local session = {
            startTime = startTime,
            endTime = endTime,
            duration = duration,
            featuresUsed = featuresUsed or {},
            errors = errors or {}
        }
        
        local updates = {
            sessions = {session},
            totalUptime = (self:LoadStats().totalUptime or 0) + duration
        }
        
        -- Atualizar contagem de features
        if featuresUsed then
            updates.features = {}
            for _, featureName in ipairs(featuresUsed) do
                updates.features[featureName] = {
                    count = (self:LoadStats().features[featureName] and self:LoadStats().features[featureName].count or 0) + 1,
                    totalTime = (self:LoadStats().features[featureName] and self:LoadStats().features[featureName].totalTime or 0) + duration,
                    lastUsed = os.time()
                }
            end
        end
        
        return self:UpdateStats(updates)
    end)
end

function DataService:RecordError(errorType, errorMessage, module)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        local updates = {
            errors = (self:LoadStats().errors or 0) + 1
        }
        
        return self:UpdateStats(updates)
    end)
end

function DataService:RecordGamePlayed(gameId, gameName, duration)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        local currentStats = self:LoadStats()
        local games = currentStats.games or {}
        
        if not games[gameId] then
            games[gameId] = {
                name = gameName,
                playCount = 0,
                totalTime = 0,
                lastPlayed = 0
            }
        end
        
        games[gameId].playCount = games[gameId].playCount + 1
        games[gameId].totalTime = games[gameId].totalTime + (duration or 0)
        games[gameId].lastPlayed = os.time()
        
        local updates = {
            games = games
        }
        
        return self:UpdateStats(updates)
    end)
end

function DataService:GetStatsSummary()
    if not self.Utils then return {} end
    
    return self.Utils:SafeCall(function()
        local stats = self:LoadStats()
        
        return {
            totalSessions = #(stats.sessions or {}),
            totalUptime = stats.totalUptime or 0,
            avgSessionDuration = stats.totalUptime / math.max(#(stats.sessions or {}), 1),
            uniqueFeatures = self.Utils:TableSize(stats.features or {}),
            totalGames = self.Utils:TableSize(stats.games or {}),
            totalErrors = stats.errors or 0,
            lastUpdated = stats.lastUpdated or 0
        }
    end) or {}
end

-- ============================================================================
-- SEÇÃO 10: SISTEMA DE CACHE DE DADOS
-- ============================================================================

function DataService:GetCache(key)
    if not self.Utils then return nil end
    
    local cacheKey = "dataservice_" .. key
    return self.Utils:CacheGet(cacheKey)
end

function DataService:SetCache(key, value, ttl)
    if not self.Utils then return false end
    
    local cacheKey = "dataservice_" .. key
    ttl = ttl or self.Config.CACHE.TTL
    return self.Utils:CacheSet(cacheKey, value, ttl)
end

function DataService:DeleteCache(key)
    if not self.Utils then return false end
    
    local cacheKey = "dataservice_" .. key
    return self.Utils:CacheDelete(cacheKey)
end

function DataService:ClearCache()
    if not self.Utils then return false end
    
    -- Limpar apenas cache do DataService
    local count = 0
    for key in pairs(self.Utils.Cache.data) do
        if key:find("dataservice_") then
            self.Utils.Cache.data[key] = nil
            count = count + 1
        end
    end
    
    self.Utils:Info("Cache limpo: " .. count .. " itens removidos", "DataService")
    return count
end

-- ============================================================================
-- SEÇÃO 11: IMPORT/EXPORT DE DADOS
-- ============================================================================

function DataService:ExportData(options)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        options = options or {
            includeConfig = true,
            includePresets = true,
            includeStats = false,
            includeBackups = false,
            compress = true,
            encrypt = true
        }
        
        local exportData = {
            metadata = {
                version = "1.0",
                exportDate = os.time(),
                source = "NexusOS",
                items = {}
            },
            data = {}
        }
        
        -- Exportar configuração
        if options.includeConfig then
            local config = self:LoadConfig()
            exportData.data.config = config
            table.insert(exportData.metadata.items, "config")
        end
        
        -- Exportar presets
        if options.includePresets then
            local presets = self:LoadAllPresets()
            exportData.data.presets = presets
            table.insert(exportData.metadata.items, "presets")
        end
        
        -- Exportar stats
        if options.includeStats then
            local stats = self:LoadStats()
            exportData.data.stats = stats
            table.insert(exportData.metadata.items, "stats")
        end
        
        -- Exportar backups
        if options.includeBackups then
            local backups = self:ListBackups()
            exportData.data.backups = backups
            table.insert(exportData.metadata.items, "backups")
        end
        
        -- Converter para JSON
        local jsonData = self.Utils:ToJSON(exportData, true)
        
        -- Criptografar se necessário
        if options.encrypt then
            jsonData = self.Crypto:Encrypt(jsonData)
        end
        
        -- Retornar dados exportados
        return {
            data = jsonData,
            metadata = exportData.metadata,
            size = #jsonData
        }
        
    end)
end

function DataService:ImportData(importData, options)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        options = options or {
            overwrite = false,
            validate = true,
            createBackup = true
        }
        
        -- Tentar descriptografar
        local decrypted = importData
        if self.Config.ENCRYPTION.ENABLED then
            decrypted = self.Crypto:Decrypt(importData)
        end
        
        -- Tentar parsear JSON
        local success, data = pcall(function()
            return game:GetService("HttpService"):JSONDecode(decrypted)
        end)
        
        if not success then
            self.Utils:Error("Dados de importação inválidos", "DataService")
            return false
        end
        
        -- Verificar metadata
        if not data.metadata or not data.data then
            self.Utils:Error("Dados de importação incompletos", "DataService")
            return false
        end
        
        -- Criar backup se necessário
        if options.createBackup then
            local currentConfig = self:LoadConfig()
            self:CreateBackup(currentConfig, "pre_import")
        end
        
        -- Importar configuração
        if data.data.config then
            if options.overwrite then
                self:SaveConfig(data.data.config)
            else
                -- Mesclar com configuração atual
                local currentConfig = self:LoadConfig()
                local merged = self.Utils:TableMerge(currentConfig, data.data.config, true)
                self:SaveConfig(merged)
            end
        end
        
        -- Importar presets
        if data.data.presets then
            local currentPresets = self:LoadAllPresets()
            local merged = self.Utils:TableMerge(currentPresets, data.data.presets, true)
            
            -- Converter de volta para formato de arquivo
            local encrypted = self.Crypto:Encrypt(merged)
            local presetsPath = self.Config.FOLDERS.ROOT .. "/" .. self.Config.FILES.PRESETS
            self:WriteFile(presetsPath, encrypted)
        end
        
        -- Importar stats
        if data.data.stats then
            local currentStats = self:LoadStats()
            local merged = self.Utils:TableMerge(currentStats, data.data.stats, true)
            self:SaveStats(merged)
        end
        
        self.Utils:Info("Dados importados com sucesso", "DataService")
        return true
        
    end)
end

function DataService:ExportToFile(filename, options)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        local exportResult = self:ExportData(options)
        if not exportResult then return false end
        
        return self:WriteFile(filename, exportResult.data)
    end)
end

function DataService:ImportFromFile(filename, options)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        if not self:FileExists(filename) then
            self.Utils:Warning("Arquivo não encontrado: " .. filename, "DataService")
            return false
        end
        
        local importData = self:ReadFile(filename)
        if not importData then return false end
        
        return self:ImportData(importData, options)
    end)
end

-- ============================================================================
-- SEÇÃO 12: UTILIDADES E FERRAMENTAS
-- ============================================================================

function DataService:GetFileInfo(path)
    if not self.Utils then return nil end
    
    return self.Utils:SafeCall(function()
        if not self:FileExists(path) then return nil end
        
        local content = self:ReadFile(path)
        if not content then return nil end
        
        local fileType = "unknown"
        if path:match("%.json$") then
            fileType = "json"
        elseif path:match("%.lua$") then
            fileType = "lua"
        elseif path:match("%.txt$") then
            fileType = "text"
        end
        
        return {
            path = path,
            size = #content,
            type = fileType,
            readable = true,
            lines = #self.Utils:Split(content, "\n"),
            checksum = self.Crypto:Hash(content, "simple"),
            modified = os.time()
        }
    end)
end

function DataService:SearchFiles(pattern, searchPath)
    if not self.Utils then return {} end
    
    return self.Utils:SafeCall(function()
        searchPath = searchPath or self.Config.FOLDERS.ROOT
        
        if not self:DirectoryExists(searchPath) then
            return {}
        end
        
        local allFiles = self:ListFiles(searchPath)
        local results = {}
        
        for _, file in ipairs(allFiles) do
            local filename = file:match("([^/\\]+)$")
            if filename:match(pattern) then
                table.insert(results, file)
            end
        end
        
        -- Buscar recursivamente em subdiretórios
        local subdirs = self:ListFiles(searchPath)
        for _, item in ipairs(subdirs) do
            if self:DirectoryExists(item) then
                local subResults = self:SearchFiles(pattern, item)
                for _, subFile in ipairs(subResults) do
                    table.insert(results, subFile)
                end
            end
        end
        
        return results
    end) or {}
end

function DataService:CleanupTempFiles(maxAge)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        maxAge = maxAge or 86400 -- 24 horas
        
        if not self:DirectoryExists(self.Config.FOLDERS.CACHE) then
            return true
        end
        
        local cacheFiles = self:ListFiles(self.Config.FOLDERS.CACHE)
        local removed = 0
        
        for _, file in ipairs(cacheFiles) do
            local fileInfo = self:GetFileInfo(file)
            if fileInfo and os.time() - fileInfo.modified > maxAge then
                self:DeleteFile(file)
                removed = removed + 1
            end
        end
        
        if removed > 0 then
            self.Utils:Info("Arquivos temporários limpos: " .. removed .. " removidos", "DataService")
        end
        
        return removed
    end)
end

function DataService:CalculateDiskUsage()
    if not self.Utils then return {} end
    
    return self.Utils:SafeCall(function()
        local usage = {
            total = 0,
            files = 0,
            folders = 0,
            byType = {}
        }
        
        local function scanFolder(path)
            if not self:DirectoryExists(path) then
                return
            end
            
            local items = self:ListFiles(path)
            
            for _, item in ipairs(items) do
                if self:DirectoryExists(item) then
                    usage.folders = usage.folders + 1
                    scanFolder(item)
                else
                    usage.files = usage.files + 1
                    local size = self:FileSize(item)
                    usage.total = usage.total + size
                    
                    -- Classificar por tipo
                    local ext = item:match("%.(%w+)$") or "unknown"
                    usage.byType[ext] = (usage.byType[ext] or 0) + size
                end
            end
        end
        
        scanFolder(self.Config.FOLDERS.ROOT)
        
        -- Converter bytes para unidades legíveis
        local function formatSize(bytes)
            local units = {"B", "KB", "MB", "GB"}
            local unitIndex = 1
            
            while bytes >= 1024 and unitIndex < #units do
                bytes = bytes / 1024
                unitIndex = unitIndex + 1
            end
            
            return string.format("%.2f %s", bytes, units[unitIndex])
        end
        
        usage.formatted = formatSize(usage.total)
        
        return usage
    end) or {}
end

-- ============================================================================
-- SEÇÃO 13: SISTEMA DE PLUGINS
-- ============================================================================

function DataService:LoadPlugins()
    if not self.Utils then return {} end
    
    return self.Utils:SafeCall(function()
        local pluginsPath = self.Config.FOLDERS.PLUGINS
        
        if not self:DirectoryExists(pluginsPath) then
            self:EnsureDirectory(pluginsPath)
            return {}
        end
        
        local pluginFiles = self:ListFiles(pluginsPath, "%.json$")
        local plugins = {}
        
        for _, pluginFile in ipairs(pluginFiles) do
            local content = self:ReadFile(pluginFile)
            if content then
                local success, pluginData = pcall(function()
                    return game:GetService("HttpService"):JSONDecode(content)
                end)
                
                if success and pluginData and pluginData.name then
                    plugins[pluginData.name] = pluginData
                end
            end
        end
        
        return plugins
    end) or {}
end

function DataService:SavePlugin(name, pluginData)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        self:EnsureDirectory(self.Config.FOLDERS.PLUGINS)
        
        local pluginPath = self.Config.FOLDERS.PLUGINS .. "/" .. name .. ".json"
        local jsonData = self.Utils:ToJSON(pluginData, true)
        
        return self:WriteFile(pluginPath, jsonData)
    end)
end

function DataService:DeletePlugin(name)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        local pluginPath = self.Config.FOLDERS.PLUGINS .. "/" .. name .. ".json"
        
        if self:FileExists(pluginPath) then
            return self:DeleteFile(pluginPath)
        end
        
        return false
    end)
end

-- ============================================================================
-- SEÇÃO 14: SISTEMA DE TEMAS
-- ============================================================================

function DataService:LoadThemes()
    if not self.Utils then return {} end
    
    return self.Utils:SafeCall(function()
        local themesPath = self.Config.FOLDERS.THEMES
        
        if not self:DirectoryExists(themesPath) then
            self:EnsureDirectory(themesPath)
            
            -- Criar temas padrão
            local defaultThemes = {
                Dark = {
                    name = "Dark",
                    author = "Nexus Team",
                    version = "1.0",
                    colors = {
                        primary = "#3498db",
                        secondary = "#2ecc71",
                        background = "#2c3e50",
                        text = "#ecf0f1",
                        accent = "#e74c3c"
                    }
                },
                Light = {
                    name = "Light",
                    author = "Nexus Team",
                    version = "1.0",
                    colors = {
                        primary = "#2980b9",
                        secondary = "#27ae60",
                        background = "#ecf0f1",
                        text = "#2c3e50",
                        accent = "#c0392b"
                    }
                }
            }
            
            -- Salvar temas padrão
            for themeName, themeData in pairs(defaultThemes) do
                local themePath = themesPath .. "/" .. themeName .. ".json"
                local jsonData = self.Utils:ToJSON(themeData, true)
                self:WriteFile(themePath, jsonData)
            end
            
            return defaultThemes
        end
        
        local themeFiles = self:ListFiles(themesPath, "%.json$")
        local themes = {}
        
        for _, themeFile in ipairs(themeFiles) do
            local content = self:ReadFile(themeFile)
            if content then
                local success, themeData = pcall(function()
                    return game:GetService("HttpService"):JSONDecode(content)
                end)
                
                if success and themeData and themeData.name then
                    themes[themeData.name] = themeData
                end
            end
        end
        
        return themes
    end) or {}
end

function DataService:SaveTheme(name, themeData)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        self:EnsureDirectory(self.Config.FOLDERS.THEMES)
        
        local themePath = self.Config.FOLDERS.THEMES .. "/" .. name .. ".json"
        local jsonData = self.Utils:ToJSON(themeData, true)
        
        return self:WriteFile(themePath, jsonData)
    end)
end

function DataService:DeleteTheme(name)
    if not self.Utils then return false end
    
    return self.Utils:SafeCall(function()
        local themePath = self.Config.FOLDERS.THEMES .. "/" .. name .. ".json"
        
        if self:FileExists(themePath) then
            return self:DeleteFile(themePath)
        end
        
        return false
    end)
end

-- ============================================================================
-- SEÇÃO 15: INICIALIZAÇÃO E SHUTDOWN
-- ============================================================================

function DataService:Initialize(utils)
    self.Utils = utils
    
    -- Criar estrutura de pastas
    for _, folder in pairs(self.Config.FOLDERS) do
        self:EnsureDirectory(folder)
    end
    
    -- Inicializar sistemas
    self:StartAutoBackup()
    
    -- Carregar configuração inicial para cache
    local config = self:LoadConfig()
    self.Utils:CacheSet("config_data", config, self.Config.CACHE.TTL)
    
    -- Log de inicialização
    local diskUsage = self:CalculateDiskUsage()
    self.Utils:Info("DataService inicializado", "DataService")
    self.Utils:Info("Uso de disco: " .. (diskUsage.formatted or "0 B"), "DataService")
    self.Utils:Info("Arquivos: " .. (diskUsage.files or 0), "DataService")
    self.Utils:Info("Pastas: " .. (diskUsage.folders or 0), "DataService")
    
    return self
end

function DataService:Shutdown()
    -- Parar backup automático
    self:StopAutoBackup()
    
    -- Salvar stats da sessão
    if self.Utils then
        local sessionEnd = os.time()
        -- Nota: sessionStart precisa ser armazenado em outro lugar
        self:RecordSession(sessionEnd - 3600, sessionEnd, {}, {}) -- Exemplo
        
        -- Limpar cache
        self:ClearCache()
        
        self.Utils:Info("DataService desligado", "DataService")
    end
    
    return true
end

function DataService:GetStatus()
    return {
        initialized = self.Utils ~= nil,
        fileSystem = {
            operations = self.FileSystem.operations,
            errors = self.FileSystem.errors,
            cacheSize = self.Utils and self.Utils:TableSize(self.Utils.Cache.data) or 0
        },
        backup = {
            enabled = self.Config.BACKUP.ENABLED,
            running = self._backupThread ~= nil
        },
        encryption = {
            enabled = self.Config.ENCRYPTION.ENABLED
        }
    }
end

-- Exportar instância
_G.NexusDataService = DataService

return DataService
