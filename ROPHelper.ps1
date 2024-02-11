$filePath = $null
$fileContent = $null
$excludedStringsFromSearch = $null

$Operations = @{
    PUSH_ESP_2_REG_LBL = "Gadgets - Push ESP to Somewhere"
    PUSH_ESP_2_REG_OPT = "2a"
    PUSH_ESP_2_REG_REX = "(?:\bpush\s+esp\b)(?:.*\bpop\s+e\w+\b)"

    MOV_ESP_2_REG_LBL = "Gadgets - Move ESP to Somewhere"
    MOV_ESP_2_REG_OPT = "2b"
    MOV_ESP_2_REG_REX = "mov\s+e\w+,\s+esp"

    MOV_ESP_2_REG_AND_PUSH_2_REG_LBL = "Gadgets - Move ESP to Somewhere + Push to Somewhere"
    MOV_ESP_2_REG_AND_PUSH_2_REG_OPT = "2c"
    MOV_ESP_2_REG_AND_PUSH_2_REG_REX = "(?:\bmov\s+e\w+,\s+esp\b)(?:.*\bpush\s+e\w+\b)"

    XCHG_REG_2_REG_LBL = "Gadgets - Exchange Operations"
    XCHG_REG_2_REG_OPT = "3a"
    XCHG_REG_2_REG_REX = "xchg\s+e\w+,\s+e\w+"

    WRITE_REG_LBL = "Gadgets - Write Operations"
    WRITE_REG_OPT = "3b"
    WRITE_REG_REX = "mov dword\s[^\n]+,\s+e\w+"

    WRITE_REG_LEA_LBL = "Gadgets - Write Operations [LEA]"
    WRITE_REG_LEA_OPT = "3c"
    WRITE_REG_LEA_REX = "lea\s+e\w+,\s[^\n]+"

    DEREF_REG_LBL = "Gadgets - Dereference Operations"
    DEREF_REG_OPT = "3d"
    DEREF_REG_REX = "mov\s+e\w+,\sdword\s[^\n]+"

    ADD_LBL = "Gadgets - Add Something"
    ADD_OPT = "4a"
    ADD_REX = "(add\s+e\w+,\s+e\w+)"

    ADD_LBL_2 = "Gadgets - Add Something to Something (Custom)"
    ADD_OPT_2 = "4b"
    ADD_REX_2 = "(add\s+PLACEHOLDER1,\s+PLACEHOLDER2)"

    SUB_LBL = "Gadgets - Sub Something"
    SUB_OPT = "4c"
    SUB_REX = "(sub\s+e\w+,\s+e\w+)"

    SUB_LBL_2 = "Gadgets - Sub Something to Something (Custom)"
    SUB_OPT_2 = "4d"
    SUB_REX_2 = "(sub\s+PLACEHOLDER1,\s+PLACEHOLDER2)"

    NEG_LBL = "Gadgets - Neg Something"
    NEG_OPT = "4e"
    NEG_REX = "(neg\s+e\w+)"

    CST_POP_2_REG_LBL = "Gadgets - Pop Something (Custom)"
    CST_POP_2_REG_OPT = "9a"
    CST_POP_2_REG_REX = "\bpop\s+PLACEHOLDER\b"

    CST_INC_2_REG_LBL = "Gadgets - Inc Something (Custom)"
    CST_INC_2_REG_OPT = "9b"
    CST_INC_2_REG_REX = "\binc\s+PLACEHOLDER\b"

    CST_DEC_2_REG_LBL = "Gadgets - Dec Something (Custom)"
    CST_DEC_2_REG_OPT = "9c"
    CST_DEC_2_REG_REX = "dec\s+PLACEHOLDER"

    CST_MOV_2_REG_LBL = "Gadgets - Move Something to Register (Custom)"
    CST_MOV_2_REG_OPT = "9d"
    CST_MOV_2_REG_REX = "mov\s+PLACEHOLDER,\s+e\w+"

    CST_MOV_REG_2_X_LBL = "Gadgets - Move Register to Somewhere (Custom)"
    CST_MOV_REG_2_X_OPT = "9e"
    CST_MOV_REG_2_X_REX = "mov\s+e\w+,\s+PLACEHOLDER"

    CST_GENERIC_QRY_LBL = "Gadgets - Generic Search"
    CST_GENERIC_QRY_OPT = "9x"

    EXIT_LBL = "Exit"
    EXIT_OPT = "x"

    STP_CONFIG_INPUT_FILE_LBL = "Setup - Configure text file"
    STP_CONFIG_INPUT_FILE_OPT = "1a"

    STP_CONFIG_EXCL_OPT_LBL = "Setup - Configure exclude string from search"
    STP_CONFIG_EXCL_OPT_OPT = "1b"
}

$Labels = @{
    ENTER_PATH_ROP_TXT = "Enter the path to the text file"
    ENTER_EXCL_STR = "Enter the excluded strings splited by '|' (i.e. call|jmp|fs:|int3)"
    PRESS_ENTER_CONTINUE = "Press Enter to continue..."
    SELECT_AN_OPT = "Select an option"
    INVALID_OPTION = "Invalid option. Please try again."
    EXITING_BYE = "Exiting the script. Goodbye!"
    ENTER_REGISTER= "Enter the register [eax | ebx | ecx | edx | esi | edi | ebp]"
    ENTER_REGEX = "Enter the regular expression"
    CONFIGURED_TEXT = "[+] Configured: "
    ERR_MSG_NO_FILE_CONFIG = "[!] No file configured"
    ERR_MSG_NO_EXCL_CONFIG = "[!] No exclusions are configured."
}

$DuckNotFoundLabel = @"
           __
        __(o )
        ===  |
           | \___/|
           \ \=== |     -    Nothing was found!
            \_\==/
              ||
             ===  tre
"@


function Show-Menu {
    Clear-Host
    
    $menu = @"
=== Menu ===

$($Operations.STP_CONFIG_INPUT_FILE_OPT). $($Operations.STP_CONFIG_INPUT_FILE_LBL)
    $(if ($global:filePath) {
        "   $($Labels.CONFIGURED_TEXT) $global:filePath"
    } else {
        "   $($Labels.ERR_MSG_NO_FILE_CONFIG)"
    })
    
$($Operations.STP_CONFIG_EXCL_OPT_OPT). $($Operations.STP_CONFIG_EXCL_OPT_LBL)
    $(if ($global:excludedStringsFromSearch) {
        "   $($Labels.CONFIGURED_TEXT) $global:excludedStringsFromSearch"
    } else {
        "   $($Labels.ERR_MSG_NO_EXCL_CONFIG)"
    })

$($Operations.PUSH_ESP_2_REG_OPT). $($Operations.PUSH_ESP_2_REG_LBL)
$($Operations.MOV_ESP_2_REG_OPT). $($Operations.MOV_ESP_2_REG_LBL)
$($Operations.MOV_ESP_2_REG_AND_PUSH_2_REG_OPT). $($Operations.MOV_ESP_2_REG_AND_PUSH_2_REG_LBL)

$($Operations.XCHG_REG_2_REG_OPT). $($Operations.XCHG_REG_2_REG_LBL)
$($Operations.WRITE_REG_OPT). $($Operations.WRITE_REG_LBL)
$($Operations.WRITE_REG_LEA_OPT). $($Operations.WRITE_REG_LEA_LBL)
$($Operations.DEREF_REG_OPT). $($Operations.DEREF_REG_LBL)

$($Operations.ADD_OPT). $($Operations.ADD_LBL)
$($Operations.ADD_OPT_2). $($Operations.ADD_LBL_2)
$($Operations.SUB_OPT). $($Operations.SUB_LBL)
$($Operations.SUB_OPT_2). $($Operations.SUB_LBL_2)
$($Operations.NEG_OPT). $($Operations.NEG_LBL)

$($Operations.CST_POP_2_REG_OPT). $($Operations.CST_POP_2_REG_LBL)
$($Operations.CST_INC_2_REG_OPT). $($Operations.CST_INC_2_REG_LBL)
$($Operations.CST_DEC_2_REG_OPT). $($Operations.CST_DEC_2_REG_LBL)
$($Operations.CST_MOV_2_REG_OPT). $($Operations.CST_MOV_2_REG_LBL)
$($Operations.CST_MOV_REG_2_X_OPT). $($Operations.CST_MOV_REG_2_X_LBL)


$($Operations.CST_GENERIC_QRY_OPT). $($Operations.CST_GENERIC_QRY_LBL)

$($Operations.EXIT_OPT). $($Operations.EXIT_LBL)
"@

    $menu | ForEach-Object { Write-Host $_ -NoNewline -ForegroundColor Cyan }
    Write-Host
}


function Get-Custom-Register {
    param(
        [string]$registerOrder
    )

    $validRegisters = 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp'

    if ($registerOrder -ne $null) {
        $registerOrder = " (" + $registerOrder + ")"
    }

    do {
        $inputValue = Read-Host ($Labels.ENTER_REGISTER + $registerOrder)
        $isValid = $validRegisters -contains $inputValue -or $inputValue -match '^e\w+$'

        if (-not $isValid) {
            Write-Host "[$inputValue] is invalid! $($Labels.ENTER_REGISTER)"
        }
    } while (-not $isValid)


    return $inputValue
}

function Get-FilePath {
    $filePathTemp = Read-Host $Labels.ENTER_PATH_ROP_TXT
    
    while (-not (Test-Path $filePathTemp -PathType Leaf)) {
        Write-Host "[!] Invalid path. Please enter a valid path."
        $filePathTemp = Read-Host $Labels.ENTER_PATH_ROP_TXT
    }

    return $filePathTemp
}

function Validate-FilePath {
    param(
        [string]$filePath
    )

    if (-not $filePath) {
        Write-Host "[!] Configure the text file first."
        return $false
    }

    return $true
}

function Run-Gadget-Search {
    param (
        [string]$searchPattern
    )

    if (-not $searchPattern) {
        Write-Host "[!] No search pattern was found..."
        return
    }

    $content = $global:fileContent

    # Apply exclusion filter if excludedStrings is provided
    if ($global:excludedStringsFromSearch) {
        $content = $content | Select-String -Pattern $global:excludedStringsFromSearch -NotMatch
    }

    $result = $content | Select-String -Pattern $searchPattern |
        ForEach-Object {
            "rop += pack('<L', " + $_.Line -replace ":", ") #"
        }

    if (-not $result) {
        Write-Host $DuckNotFoundLabel
        return
    }

    Write-Host ("-" * 80)
    foreach ($line in $result) {
        Write-Host $line
    }
    Write-Host ("-" * 80)

    return
}

function Execute-Option {
    param(
        [string]$option
    )

    switch ($option.ToLower()) {
        $Operations.STP_CONFIG_INPUT_FILE_OPT {
            $global:filePath = Get-FilePath
            Write-Host "$($Labels.CONFIGURED_TEXT) $global:filePath"
            $global:fileContent = Get-Content -Path $global:filePath
        }
        $Operations.STP_CONFIG_EXCL_OPT_OPT {
            if ($global:excludedStringsFromSearch) {
                Write-Host "$($Labels.CONFIGURED_TEXT) [$global:excludedStringsFromSearch]"
            }

            $global:excludedStringsFromSearch = Read-Host $Labels.ENTER_EXCL_STR
        }

        $Operations.PUSH_ESP_2_REG_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.PUSH_ESP_2_REG_LBL
            }

            Run-Gadget-Search -searchPattern $Operations.PUSH_ESP_2_REG_REX
        }
        $Operations.MOV_ESP_2_REG_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.MOV_ESP_2_REG_LBL
            }

            Run-Gadget-Search -searchPattern $Operations.MOV_ESP_2_REG_REX
        }
        $Operations.MOV_ESP_2_REG_AND_PUSH_2_REG_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.MOV_ESP_2_REG_AND_PUSH_2_REG_LBL
            }

            Run-Gadget-Search -searchPattern $Operations.MOV_ESP_2_REG_AND_PUSH_2_REG_REX
        }

        $Operations.XCHG_REG_2_REG_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.XCHG_REG_2_REG_LBL
            }

            Run-Gadget-Search -searchPattern $Operations.XCHG_REG_2_REG_REX
        }
        $Operations.WRITE_REG_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.WRITE_REG_LBL
            }

            Run-Gadget-Search -searchPattern $Operations.WRITE_REG_REX
        }
        $Operations.WRITE_REG_LEA_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.WRITE_REG_LEA_LBL
            }

            Run-Gadget-Search -searchPattern $Operations.WRITE_REG_LEA_REX
        }
        $Operations.DEREF_REG_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.DEREF_REG_LBL
            }

            Run-Gadget-Search -searchPattern $Operations.DEREF_REG_REX
        }

        $Operations.ADD_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.ADD_LBL
            }

            Run-Gadget-Search -searchPattern $Operations.ADD_REX
        }
        $Operations.ADD_OPT_2 {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.ADD_LBL_2
            }

            $register1 = Get-Custom-Register "1"
            $register2 = Get-Custom-Register "2"

            $expression = $Operations.ADD_REX_2.Replace("PLACEHOLDER1", $register1).Replace("PLACEHOLDER2", $register2)
            Write-Host $expression

            Run-Gadget-Search -searchPattern $expression
        }
        $Operations.SUB_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.SUB_LBL
            }

            Run-Gadget-Search -searchPattern $Operations.SUB_REX
        }
        $Operations.SUB_OPT_2 {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.SUB_LBL_2
            }

            $register1 = Get-Custom-Register "1"
            $register2 = Get-Custom-Register "2"

            $expression = $Operations.SUB_REX_2.Replace("PLACEHOLDER1", $register1).Replace("PLACEHOLDER2", $register2)
            Write-Host $expression

            Run-Gadget-Search -searchPattern $expression
        }
        $Operations.NEG_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.NEG_LBL
            }

            Run-Gadget-Search -searchPattern $Operations.NEG_REX
        }

        $Operations.CST_POP_2_REG_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.CST_POP_2_REG_LBL
            }

            $register = Get-Custom-Register

            Run-Gadget-Search -searchPattern $Operations.CST_POP_2_REG_REX.Replace("PLACEHOLDER", $register)
        }
        $Operations.CST_INC_2_REG_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.CST_INC_2_REG_LBL
            }

            $register = Get-Custom-Register

            Run-Gadget-Search -searchPattern $Operations.CST_INC_2_REG_REX.Replace("PLACEHOLDER", $register) 
        }
        $Operations.CST_DEC_2_REG_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.CST_DEC_2_REG_LBL
            }

            $register = Get-Custom-Register

            Run-Gadget-Search -searchPattern $Operations.CST_DEC_2_REG_REX.Replace("PLACEHOLDER", $register)
        }
        $Operations.CST_MOV_2_REG_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.CST_MOV_2_REG_LBL
            }

            $register = Get-Custom-Register

            $searchPattern = $Operations.CST_MOV_2_REG_REX.Replace("PLACEHOLDER", $register)

            Write-Host $searchPattern

            Run-Gadget-Search -searchPattern $searchPattern
        }
        $Operations.CST_MOV_REG_2_X_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.CST_MOV_REG_2_X_LBL
            }

            $register = Get-Custom-Register

            $searchPattern = $Operations.CST_MOV_REG_2_X_REX.Replace("PLACEHOLDER", $register)

            Run-Gadget-Search -searchPattern $searchPattern
        }
        $Operations.CST_GENERIC_QRY_OPT {
            if (Validate-FilePath -filePath $global:filePath) {
                Write-Host $Operations.CST_GENERIC_QRY_LBL
            }

            $re = Read-Host $Labels.ENTER_REGEX
            while (-not $re) {
                Write-Host "Regular expression cannot be empty"
                $register = Read-Host $Labels.ENTER_REGEX
            }

            Run-Gadget-Search -searchPattern $re
        }
        
        $Operations.EXIT_OPT {
            Write-Host
            Write-Host $Labels.EXITING_BYE
            exit
        }

        default {
            Write-Host
            Write-Host $Labels.INVALID_OPTION
        }
    }
}

while ($true) {
    
    Show-Menu 

    $selectedOption = Read-Host $Labels.SELECT_AN_OPT

    Execute-Option -option $selectedOption

    Write-Host
    Read-Host $Labels.PRESS_ENTER_CONTINUE
}
