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
    Write-Host "      ano 'to   : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Pinapatay ang Windows tracking at nila-lock ang memory." -ForegroundColor Gray
    Write-Host "      bakit     : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Para hindi ma-dump ang passwords mo sa LSASS gamit ang Mimikatz." -ForegroundColor DarkGray
    Write-Host "      command   : " -ForegroundColor DarkGray -NoNewline
    Write-Host "2" -ForegroundColor Green
    Start-Sleep -Milliseconds 250

    # 2. VPN & Browser
    Write-Host "`n  [2] vpn & browser shield" -ForegroundColor White
    Write-Host "      ano 'to   : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Mullvad tunnel lock + anti-WebRTC leak sa browser." -ForegroundColor Gray
    Write-Host "      bakit     : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Para hindi sumingaw ang totoong IP mo at immune sa stealer malware." -ForegroundColor DarkGray
    Write-Host "      command   : " -ForegroundColor DarkGray -NoNewline
    Write-Host "mullvad harden" -ForegroundColor Green
    Start-Sleep -Milliseconds 250

    # 3. Public Sentry
    Write-Host "`n  [3] public sentry (pang-cafe o airport)" -ForegroundColor White
    Write-Host "      ano 'to   : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Tripwire kapag nakakabit sa pampublikong Wi-Fi." -ForegroundColor Gray
    Write-Host "      bakit     : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Kapag may nag-scan sa'yo o nag-plug ng BadUSB, auto-cut agad ang net at lock ang PC." -ForegroundColor DarkGray
    Write-Host "      command   : " -ForegroundColor DarkGray -NoNewline
    Write-Host "sentry -autopanic" -ForegroundColor Green
    Start-Sleep -Milliseconds 250

    # 4. Anti-Forensics & Camouflage
    Write-Host "`n  [4] anti-forensics & camouflage" -ForegroundColor White
    Write-Host "      ano 'to   : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Linis ng logs sabay tanim ng normal na civilian files." -ForegroundColor Gray
    Write-Host "      bakit     : " -ForegroundColor DarkGray -NoNewline
    Write-Host "Delikado ang sobrang linis na laptop sa forensics. Kailangan magmukhang ordinaryong user." -ForegroundColor DarkGray
    Write-Host "      command   : " -ForegroundColor DarkGray -NoNewline
    Write-Host "chameleon" -ForegroundColor Green
    Start-Sleep -Milliseconds 250

    # 5. Cheat code
    Write-Host "`n  [5] para sa mga tinatamad o nalilito" -ForegroundColor White
    Write-Host "      Kung diko magets ang commands, i-type mo lang ito sa prompt:" -ForegroundColor Gray
    Write-Host "`n          quick`n" -ForegroundColor Green
    Write-Host "      1-click menu lang yan para sa Cafe Mode, Lockdown, o Linis." -ForegroundColor DarkGray

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
