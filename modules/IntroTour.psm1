# IntroTour.psm1 - Cybernetic Onboarding, Voice Briefing & Script-Kiddie Friendly Tour
# WinOpSec Sovereign Tier Multimedia Module

function Speak-AudioVoice {
    param(
        [string]$Text,
        [switch]$Wait
    )

    # 1. Try SAPI.SpVoice (COM)
    try {
        $voice = New-Object -ComObject SAPI.SpVoice -ErrorAction Stop
        $voice.Rate = 0
        $voice.Volume = 100
        $flags = if ($Wait) { 0 } else { 1 } # 1 = SVSFlagsAsync
        $voice.Speak($Text, $flags) | Out-Null
        return
    } catch {}

    # 2. Try System.Speech.Synthesis (.NET)
    try {
        Add-Type -AssemblyName System.Speech -ErrorAction Stop
        $synth = New-Object System.Speech.Synthesis.SpeechSynthesizer -ErrorAction Stop
        $synth.Rate = 0
        $synth.Volume = 100
        if ($Wait) {
            $synth.Speak($Text)
        } else {
            $synth.SpeakAsync($Text) | Out-Null
        }
        return
    } catch {}
}

function Play-CyberBeep {
    param([int]$Freq = 1200, [int]$DurationMs = 80)
    try {
        [Console]::Beep($Freq, $DurationMs)
    } catch {}
}

function Test-ConsoleKeyAvailable {
    try {
        if ([System.Console]::IsInputRedirected) { return $false }
        return [System.Console]::KeyAvailable
    } catch {
        return $false
    }
}

function Write-AnimatedLine {
    param(
        [string]$Text,
        [int]$CharDelayMs = 15,
        [ConsoleColor]$Color = "White",
        [switch]$NoNewline
    )

    $interrupted = $false
    foreach ($char in $Text.ToCharArray()) {
        Write-Host $char -ForegroundColor $Color -NoNewline
        if ($CharDelayMs -gt 0) {
            Start-Sleep -Milliseconds $CharDelayMs
        }
        if (Test-ConsoleKeyAvailable) {
            try {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq [ConsoleKey]::Spacebar -or $key.Key -eq [ConsoleKey]::Enter -or $key.Key -eq [ConsoleKey]::Escape) {
                    $interrupted = $true
                    $idx = $Text.IndexOf($char)
                    if ($idx -lt ($Text.Length - 1)) {
                        Write-Host $Text.Substring($idx + 1) -ForegroundColor $Color -NoNewline
                    }
                    break
                }
            } catch {}
        }
    }
    if (-not $NoNewline) { Write-Host "" }
}

function Invoke-CyberIntro {
    [CmdletBinding()]
    param(
        [switch]$VoiceMute,
        [switch]$Fast
    )

    Clear-Host

    $delay = if ($Fast) { 0 } else { 20 }

    Write-Host ""
    Write-Host "  ================================================================================" -ForegroundColor DarkCyan

    $asciiHello = @(
        "      __  __     ______     __         __         ______    ",
        "     /\ \_\ \   /\  ___\   /\ \       /\ \       /\  __ \   ",
        "     \ \  __ \  \ \  __\   \ \ \____  \ \ \____  \ \ \/\ \  ",
        "      \ \_\ \_\  \ \_____\  \ \_____\  \ \_____\  \ \_____\ ",
        "       \/_/\/_/   \/_____/   \/_____/   \/_____/   \/_____/ "
    )

    foreach ($line in $asciiHello) {
        Write-Host $line -ForegroundColor Cyan
        Start-Sleep -Milliseconds 30
    }

    Write-Host "  ================================================================================" -ForegroundColor DarkCyan
    Write-Host "  [PRESS ANY KEY OR SPACEBAR TO SKIP ANIMATION]`n" -ForegroundColor DarkGray

    Play-CyberBeep -Freq 900 -DurationMs 100
    Play-CyberBeep -Freq 1400 -DurationMs 120

    if (-not $VoiceMute) {
        Speak-AudioVoice -Text "Hello. Welcome to WinOpSec. System integrity verified."
    }

    $greetings = @(
        @{ Lang = "EN"; Text = "> Hello." },
        @{ Lang = "TL"; Text = "> Kumusta." },
        @{ Lang = "ES"; Text = "> Hola." },
        @{ Lang = "FR"; Text = "> Bonjour." },
        @{ Lang = "JA"; Text = "> Konnichiwa." },
        @{ Lang = "SYS"; Text = "> SOVEREIGN DEFENSE MATRIX INITIALIZED." }
    )

    foreach ($g in $greetings) {
        $color = if ($g.Lang -eq "SYS") { "Green" } else { "Gray" }
        Write-AnimatedLine -Text ("  {0,-4} {1}" -f "[$($g.Lang)]", $g.Text) -CharDelayMs $delay -Color $color
        Start-Sleep -Milliseconds 120
    }

    Write-Host ""
    Play-CyberBeep -Freq 1800 -DurationMs 150

    Write-Host "  --------------------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [ OPERATOR ONBOARDING BRIEFING: HOW TO WIELD WINOPSEC ]" -ForegroundColor Yellow
    Write-Host "  --------------------------------------------------------------------------------`n" -ForegroundColor DarkGray

    if (-not $VoiceMute) {
        Speak-AudioVoice -Text "Here is your operational briefing."
    }

    # Chapter 1
    Write-Host "  [01] THE SHIELD // HOST HARDENING" -ForegroundColor Cyan
    Write-Host "       What it does : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Locks kernel memory, kills telemetry, and blocks passwords theft." -ForegroundColor White
    Write-Host "       Why you care : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Stops Mimikatz from stealing credentials, disables hiberfil RAM bleeds," -ForegroundColor Gray
    Write-Host "                      and blocks Thunderbolt PCILeech physical memory attacks." -ForegroundColor Gray
    Write-Host "       Quick key    : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Type '2' (telemetry) in the prompt.`n" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 400

    # Chapter 2
    Write-Host "  [02] THE GHOST // QUANTUM VPN & BROWSER SHIELD" -ForegroundColor Cyan
    Write-Host "       What it does : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Enforces Mullvad WFP killswitch, DAITA traffic shaping & anti-stealers." -ForegroundColor White
    Write-Host "       Why you care : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Encrypts tunnel with Kyber-1024, blocks WebRTC IP leaks, and locks" -ForegroundColor Gray
    Write-Host "                      browser SQLite password vaults from Lumma/RedLine infostealers." -ForegroundColor Gray
    Write-Host "       Quick key    : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Type 'mullvad harden' or 'browser'`n" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 400

    # Chapter 3
    Write-Host "  [03] THE SENTRY // PUBLIC WI-FI TRIPWIRE" -ForegroundColor Cyan
    Write-Host "       What it does : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Real-time perimeter surveillance for hostile public networks." -ForegroundColor White
    Write-Host "       Why you care : " -ForegroundColor DarkGray -NoNewline
    Write-Host "If someone on your cafe Wi-Fi does ARP poisoning (Bettercap), port scans," -ForegroundColor Gray
    Write-Host "                      or plugs in a Rubber Ducky BadUSB, it severs net and locks PC." -ForegroundColor Gray
    Write-Host "       Quick key    : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Type 'sentry -autopanic' when sitting in public.`n" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 400

    # Chapter 4
    Write-Host "  [04] THE CHAMELEON // FORENSIC PLAUSIBLE DENIABILITY" -ForegroundColor Cyan
    Write-Host "       What it does : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Neutralizes execution logs & seeds innocent civilian activity." -ForegroundColor White
    Write-Host "       Why you care : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Defeats the SANS FOR500 'Too Clean Machine' trap. Wipes PCA/ShellBags," -ForegroundColor Gray
    Write-Host "                      then plants synthetic student/civilian docs so you blend in." -ForegroundColor Gray
    Write-Host "       Quick key    : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Type 'chameleon' to deploy noise; 'chameleon -purge' to remove.`n" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 400

    # Chapter 5 - The Script Kiddie Friendly Cheat Code
    Write-Host "  [05] THE CHEAT CODE // GUIDED SCENARIO WIZARD" -ForegroundColor Green
    Write-Host "       If you don't know what command to use, just type:" -ForegroundColor White
    Write-Host "`n           quick`n" -ForegroundColor Green
    Write-Host "       1-click buttons for: Cafe Mode, Full Lockdown, Ephemeral Browse, or Scrub!" -ForegroundColor DarkGray
    Write-Host "  --------------------------------------------------------------------------------`n" -ForegroundColor DarkGray

    if (-not $VoiceMute) {
        Speak-AudioVoice -Text "If you get lost, just type quick. WinOpSec will handle the rest. System ready."
    }

    Play-CyberBeep -Freq 1500 -DurationMs 100
    Play-CyberBeep -Freq 2200 -DurationMs 150

    Write-Host "  [+] Operator briefing complete. Press any key to enter main console... " -ForegroundColor Cyan -NoNewline
    try {
        if (-not [System.Console]::IsInputRedirected) {
            $null = [Console]::ReadKey($true)
        }
    } catch {}
    Write-Host "`n"
}

Export-ModuleMember -Function Invoke-CyberIntro, Speak-AudioVoice
