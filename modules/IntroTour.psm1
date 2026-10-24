# IntroTour.psm1 - Interactive Onboarding & Quick Briefing
# WinOpSec Operational Utility

function Speak-AudioVoice {
    param(
        [string]$Text,
        [switch]$Wait
    )

    try {
        $voice = New-Object -ComObject SAPI.SpVoice -ErrorAction Stop
        $voice.Rate = 1
        $voice.Volume = 100
        $flags = if ($Wait) { 0 } else { 1 }
        $voice.Speak($Text, $flags) | Out-Null
        return
    } catch {}

    try {
        Add-Type -AssemblyName System.Speech -ErrorAction Stop
        $synth = New-Object System.Speech.Synthesis.SpeechSynthesizer -ErrorAction Stop
        $synth.Rate = 1
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
    param([int]$Freq = 1000, [int]$DurationMs = 60)
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
        [int]$CharDelayMs = 12,
        [ConsoleColor]$Color = "Gray",
        [switch]$NoNewline
    )

    foreach ($char in $Text.ToCharArray()) {
        Write-Host $char -ForegroundColor $Color -NoNewline
        if ($CharDelayMs -gt 0) {
            Start-Sleep -Milliseconds $CharDelayMs
        }
        if (Test-ConsoleKeyAvailable) {
            try {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq [ConsoleKey]::Spacebar -or $key.Key -eq [ConsoleKey]::Enter -or $key.Key -eq [ConsoleKey]::Escape) {
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

    $delay = if ($Fast) { 0 } else { 15 }

    Write-Host ""
    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray

    $asciiHello = @(
        "    _  _     _ _       ",
        "   | || |___| | |___   ",
        "   | __ / -_) | / _ \  ",
        "   |_||_\___|_|_\___/  "
    )

    foreach ($line in $asciiHello) {
        Write-Host "  $line" -ForegroundColor White
        Start-Sleep -Milliseconds 25
    }

    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [press space or enter to skip]`n" -ForegroundColor DarkGray

    Play-CyberBeep -Freq 800 -DurationMs 60
    Play-CyberBeep -Freq 1200 -DurationMs 80

    if (-not $VoiceMute) {
        Speak-AudioVoice -Text "WinOpSec ready. Don't do stupid shit on public Wi-Fi. If you don't know the commands, just type quick."
    }

    Write-AnimatedLine -Text "  > hello." -CharDelayMs $delay -Color Gray
    Start-Sleep -Milliseconds 100
    Write-AnimatedLine -Text "  > kumusta." -CharDelayMs $delay -Color Gray
    Start-Sleep -Milliseconds 100
    Write-AnimatedLine -Text "  > winopsec ready." -CharDelayMs $delay -Color Green
    Start-Sleep -Milliseconds 150

    Write-Host ""
    Play-CyberBeep -Freq 1400 -DurationMs 80

    Write-Host "  -- quick operator briefing ---------------------------------" -ForegroundColor DarkGray

    # 1. Host Hardening
    Write-Host "`n  [1] host hardening" -ForegroundColor White
    Write-Host "      what it is  : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Kills background tracking and locks kernel memory." -ForegroundColor Gray
    Write-Host "      why you care: " -ForegroundColor DarkGray -NoNewline
    Write-Host "Stops Mimikatz from dumping credentials out of LSASS memory." -ForegroundColor DarkGray
    Write-Host "      command     : " -ForegroundColor DarkGray -NoNewline
    Write-Host "2" -ForegroundColor Green
    Start-Sleep -Milliseconds 250

    # 2. VPN & Browser
    Write-Host "`n  [2] vpn & browser shield" -ForegroundColor White
    Write-Host "      what it is  : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Mullvad tunnel lock and browser WebRTC leak kill." -ForegroundColor Gray
    Write-Host "      why you care: " -ForegroundColor DarkGray -NoNewline
    Write-Host "Keeps your real IP hidden and locks vaults against stealers." -ForegroundColor DarkGray
    Write-Host "      command     : " -ForegroundColor DarkGray -NoNewline
    Write-Host "mullvad harden" -ForegroundColor Green
    Start-Sleep -Milliseconds 250

    # 3. Public Sentry
    Write-Host "`n  [3] public sentry (cafes & public wi-fi)" -ForegroundColor White
    Write-Host "      what it is  : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Real-time tripwire for hostile local networks." -ForegroundColor Gray
    Write-Host "      why you care: " -ForegroundColor DarkGray -NoNewline
    Write-Host "If someone arpspoofs you or plugs in a BadUSB, it drops the net and locks the screen." -ForegroundColor DarkGray
    Write-Host "      command     : " -ForegroundColor DarkGray -NoNewline
    Write-Host "sentry -autopanic" -ForegroundColor Green
    Start-Sleep -Milliseconds 250

    # 4. Anti-Forensics & Camouflage
    Write-Host "`n  [4] anti-forensics & camouflage" -ForegroundColor White
    Write-Host "      what it is  : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Wipes execution logs and plants civilian decoy files." -ForegroundColor Gray
    Write-Host "      why you care: " -ForegroundColor DarkGray -NoNewline
    Write-Host "An empty laptop is suspicious to forensic investigators; blend in instead." -ForegroundColor DarkGray
    Write-Host "      command     : " -ForegroundColor DarkGray -NoNewline
    Write-Host "chameleon" -ForegroundColor Green
    Start-Sleep -Milliseconds 250

    # 5. Quick Menu
    Write-Host "`n  [5] the quick menu" -ForegroundColor White
    Write-Host "      If you don't feel like typing commands, just run:" -ForegroundColor Gray
    Write-Host "`n          quick`n" -ForegroundColor Green
    Write-Host "      1-click profiles for Cafe Mode, Full Lockdown, or Clean." -ForegroundColor DarkGray

    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  press any key to start... " -ForegroundColor DarkGray -NoNewline
    try {
        if (-not [System.Console]::IsInputRedirected) {
            $null = [Console]::ReadKey($true)
        }
    } catch {}
    Write-Host "`n"
}

Export-ModuleMember -Function Invoke-CyberIntro, Speak-AudioVoice
