--[[ Демонстрационный options.lua для тренировки инструмента ablua.

     Это упрощённая копия файла настроек клиента PC-версии Angry Birds:
     такой файл лежит в data/scripts/options.lua и зашифрован AES-256-CBC.

     Обратите внимание: кроме двух «служебных» флагов здесь есть и обычные
     настройки со значением true — они должны остаться включёнными после
     активации.
]]

gamelua = gamelua or {}

-- Служебные флаги, из-за которых игра просит регистрацию и лезет в интернет
gamelua.g_registrationEnabled = true
gamelua.g_updateCheckEnabled = true

-- Обычные настройки игрока
gamelua.g_language = "ru"
gamelua.g_soundEnabled = true
gamelua.g_musicEnabled = true
gamelua.g_fullscreen = false
gamelua.g_showFPS = false
gamelua.g_levelUnlocked = nil

local function describe(value)
    if value == nil then
        return "nil"
    end
    return tostring(value)
end

-- Мини-отчёт, чтобы демонстрацию можно было проверить глазами
function gamelua.dumpOptions()
    local names = {
        "g_registrationEnabled",
        "g_updateCheckEnabled",
        "g_language",
        "g_soundEnabled",
        "g_musicEnabled",
        "g_fullscreen",
    }
    for _, name in ipairs(names) do
        print(string.format("%s = %s", name, describe(gamelua[name])))
    end
end

return gamelua
