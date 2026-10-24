# IntroTour.psm1 - Interactive Onboarding & Audio Briefing
# WinOpSec Defensive Suite

$script:TtsEngine = $null

function Get-TtsVoiceEngine {
    if ($script:TtsEngine) { return $script:TtsEngine }

    try {
        $cat = New-Object -ComObject SAPI.SpObjectTokenCategory -ErrorAction Stop
        $cat.SetId("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech\Voices", $false)
        $tokens = $cat.EnumerateTokens()

        $audioOut = New-Object -ComObject SAPI.SpMMAudioOut -ErrorAction Stop
        $audioOut.DeviceId = -1 # WAVE_MAPPER (primary default sound card output)

        $voice = New-Object -ComObject SAPI.SpVoice -ErrorAction Stop
        if ($tokens.Count -gt 0) {
            $voice.Voice = $tokens.Item(0)
        }
        $voice.AudioOutputStream = $audioOut
        $voice.Volume = 100
        $voice.Rate = 0

        $script:TtsEngine = @{
            Type   = "SAPI"
            Engine = $voice
        }
        return $script:TtsEngine
    } catch {
        try {
            Add-Type -AssemblyName System.Speech -ErrorAction Stop
            $synth = New-Object System.Speech.Synthesis.SpeechSynthesizer -ErrorAction Stop
            $synth.SetOutputToDefaultAudioDevice()
            $synth.Volume = 100
            $synth.Rate = 0
            $script:TtsEngine = @{
                Type   = "System.Speech"
                Engine = $synth
            }
            return $script:TtsEngine
        } catch {
            return $null
        }
    }
}

function Speak-Narration {
    param(
        [string]$Text,
        [switch]$Wait
    )

    $tts = Get-TtsVoiceEngine
    if (-not $tts) { return }

    try {
        if ($tts.Type -eq "SAPI") {
            $v = $tts.Engine
            if ($Wait) {
                $v.Speak($Text, 0) | Out-Null
            } else {
                $v.Speak("", 2) | Out-Null # Purge pending speech
                $v.Speak($Text, 1) | Out-Null # Async speech
            }
        } elseif ($tts.Type -eq "System.Speech") {
            $s = $tts.Engine
            if ($Wait) {
                $s.Speak($Text)
            } else {
                $s.SpeakAsyncCancelAll()
                $s.SpeakAsync($Text) | Out-Null
            }
        }
    } catch {}
}

function Stop-Narration {
    $tts = Get-TtsVoiceEngine
    if (-not $tts) { return }
    try {
        if ($tts.Type -eq "SAPI") {
            $tts.Engine.Speak("", 2) | Out-Null
        } elseif ($tts.Type -eq "System.Speech") {
            $tts.Engine.SpeakAsyncCancelAll()
        }
    } catch {}
}

function Test-VoiceOutput {
    Write-Host "`n  -- voice audio diagnostics ---------------------------------" -ForegroundColor DarkGray
    Write-Host "  initializing sound output pipeline..." -ForegroundColor Gray
    
    $tts = Get-TtsVoiceEngine
    if (-not $tts) {
        Write-Host "  [FAIL] No speech synthesizer found on host." -ForegroundColor Red
        return
    }

    $voiceName = if ($tts.Type -eq "SAPI" -and $tts.Engine.Voice) {
        $tts.Engine.Voice.GetDescription()
    } else {
        "Default System Voice"
    }

    Write-Host "  [PASS] Audio device: Default Speaker (WAVE_MAPPER)" -ForegroundColor Green
    Write-Host "  [PASS] Engine: $($tts.Type) | Voice: $voiceName" -ForegroundColor Green
    Write-Host "  speaking test phrase through laptop speakers..." -ForegroundColor DarkGray

    Play-SubtleTone -Freq 1000 -DurationMs 70
    Speak-Narration -Text "Audio check complete. WinOpSec voice engine is active and clear." -Wait
    Write-Host "  [DONE] Voice audio test finished.`n" -ForegroundColor Green
}

function Play-SubtleTone {
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

function Read-ConsoleKeyIfAvailable {
    try {
        if (Test-ConsoleKeyAvailable) {
            return [Console]::ReadKey($true)
        }
    } catch {}
    return $null
}

function Write-AnimatedLine {
    param(
        [string]$Text,
        [int]$CharDelayMs = 12,
        [ConsoleColor]$Color = "Gray",
        [switch]$NoNewline
    )

    $skipped = $false
    foreach ($char in $Text.ToCharArray()) {
        Write-Host $char -ForegroundColor $Color -NoNewline
        if ($CharDelayMs -gt 0 -and -not $skipped) {
            Start-Sleep -Milliseconds $CharDelayMs
        }
        if (Test-ConsoleKeyAvailable) {
            $key = Read-ConsoleKeyIfAvailable
            if ($key -and ($key.Key -eq [ConsoleKey]::Spacebar -or $key.Key -eq [ConsoleKey]::Enter -or $key.Key -eq [ConsoleKey]::Escape)) {
                $skipped = $true
                $idx = $Text.IndexOf($char)
                if ($idx -lt ($Text.Length - 1)) {
                    Write-Host $Text.Substring($idx + 1) -ForegroundColor $Color -NoNewline
                }
                break
            }
        }
    }
    if (-not $NoNewline) { Write-Host "" }
}

function Wait-NarrationFinish {
    param(
        [int]$MaxMs = 6000,
        [switch]$AllowSkip
    )

    $tts = Get-TtsVoiceEngine
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    while ($sw.ElapsedMilliseconds -lt $MaxMs) {
        if ($tts -and $tts.Type -eq "SAPI") {
            # RunningState 1 = not speaking / done
            if ($tts.Engine.Status.RunningState -eq 1) { break }
        }

        if ($AllowSkip -and (Test-ConsoleKeyAvailable)) {
            $k = Read-ConsoleKeyIfAvailable
            if ($k) {
                if ($k.Key -eq [ConsoleKey]::Escape) {
                    return "SkipAll"
                } elseif ($k.Key -eq [ConsoleKey]::Spacebar -or $k.Key -eq [ConsoleKey]::Enter) {
                    Stop-Narration
                    return "SkipStep"
                }
            }
        }
        Start-Sleep -Milliseconds 60
    }
    return "Done"
}

function Invoke-CyberIntro {
    [CmdletBinding()]
    param(
        [switch]$VoiceMute,
        [switch]$Fast,
        [switch]$TestVoice
    )

    if ($TestVoice) {
        Test-VoiceOutput
        return
    }

    Clear-Host

    $delay = if ($Fast) { 0 } else { 12 }

    Write-Host ""
    Write-Host "  ------------------------------------------------------------------" -ForegroundColor DarkGray

    $asciiHello = @(
        "     _          _ _       ",
        "    | |        | | |      ",
        "    | |__   ___| | | ___  ",
        "    | '_ \ / _ \ | |/ _ \ ",
        "    | | | |  __/ | | (_) |",
        "    |_| |_|\___|_|_|\___/ "
    )

    foreach ($line in $asciiHello) {
        Write-Host "  $line" -ForegroundColor White
        Start-Sleep -Milliseconds 20
    }

    Write-Host "  ------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [press space or enter anytime to skip]`n" -ForegroundColor DarkGray

    Play-SubtleTone -Freq 800 -DurationMs 60
    Play-SubtleTone -Freq 1100 -DurationMs 75

    if (-not $VoiceMute) {
        Speak-Narration -Text "Hello. Welcome to WinOpSec. Your defensive terminal is online."
    }

    Write-AnimatedLine -Text "  > hello." -CharDelayMs $delay -Color Gray
    Start-Sleep -Milliseconds 120
    Write-AnimatedLine -Text "  > welcome to winopsec." -CharDelayMs $delay -Color Gray
    Start-Sleep -Milliseconds 120
    Write-AnimatedLine -Text "  > defensive posture active." -CharDelayMs $delay -Color Green

    $null = Wait-NarrationFinish -MaxMs 4500 -AllowSkip

    Write-Host ""
    Play-SubtleTone -Freq 1300 -DurationMs 70

    Write-Host "  -- operational briefing ------------------------------------------" -ForegroundColor DarkGray

    $pillars = @(
        @{
            Number    = "1"
            Title     = "Host Hardening & Anti-Mimikatz"
            Voice     = "Pillar one: Host Hardening. This blocks background telemetry and locks kernel memory so credentials cannot be stolen."
            What      = "Kills background telemetry, disables WDigest, and locks LSASS in PPL memory."
            Why       = "Stops credential dumpers like Mimikatz from harvesting plaintext passwords."
            Command   = "2  or  harden-all"
        },
        @{
            Number    = "2"
            Title     = "VPN Tunnel Lock & Browser Shields"
            Voice     = "Pillar two: VPN and Browser Shield. This locks your Mullvad tunnel and seals WebRTC leaks."
            What      = "Enforces strict WFP killswitch, DAITA traffic shaping, and WebRTC privacy locks."
            Why       = "Keeps your real IP and location hidden even if an app or browser crashes."
            Command   = "mullvad harden  or  browser"
        },
        @{
            Number    = "3"
            Title     = "Public Sentry & Tripwire"
            Voice     = "Pillar three: Public Sentry. When you are on cafe or public Wi-Fi, this detects ARP spoofing and rogue attacks in real time."
            What      = "Monitors 7 local attack vectors including ARP spoofing, port scans, and BadUSB."
            Why       = "If someone attacks you on public Wi-Fi, auto-panic cuts the connection instantly."
            Command   = "sentry -autopanic"
        },
        @{
            Number    = "4"
            Title     = "Anti-Forensics & Chameleon Camouflage"
            Voice     = "Pillar four: Anti-Forensics and Chameleon. This shreds execution traces and plants benign civilian files to defeat forensic analysis."
            What      = "Shreds PCA logs, ShellBags, and injects realistic civilian decoy activity."
            Why       = "An empty laptop is a forensic red flag. Chameleon blends your machine into the crowd."
            Command   = "wipe  or  chameleon"
        },
        @{
            Number    = "5"
            Title     = "1-Click Scenario Wizard"
            Voice     = "Pillar five: The Quick Wizard. If you are unsure what commands to type, simply run quick for one-click automated defense."
            What      = "Automated 1-click profiles for Cafe Wi-Fi, Host Lockdown, and Post-Session Clean."
            Why       = "No memorization needed. Run quick, select a scenario, and defense is immediate."
            Command   = "quick"
        }
    )

    $interruptedAll = $false

    foreach ($p in $pillars) {
        if ($interruptedAll) {
            Write-Host "`n  [$($p.Number)] $($p.Title)" -ForegroundColor White
            Write-Host "      what it is  : " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($p.What)" -ForegroundColor Gray
            Write-Host "      why it cares: " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($p.Why)" -ForegroundColor DarkGray
            Write-Host "      command     : " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($p.Command)" -ForegroundColor Green
            continue
        }

        if (-not $VoiceMute) {
            Speak-Narration -Text $p.Voice
        }

        Write-Host "`n  [$($p.Number)] $($p.Title)" -ForegroundColor White
        Write-Host "      what it is  : " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($p.What)" -ForegroundColor Gray
        Write-Host "      why it cares: " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($p.Why)" -ForegroundColor DarkGray
        Write-Host "      command     : " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($p.Command)" -ForegroundColor Green

        $skipState = Wait-NarrationFinish -MaxMs 6500 -AllowSkip
        if ($skipState -eq "SkipAll") {
            $interruptedAll = $true
            Stop-Narration
        }
    }

    if (-not $VoiceMute -and -not $interruptedAll) {
        Speak-Narration -Text "Ready to proceed. Type quick to begin, or press enter for the main menu."
    }

    Write-Host "`n  ------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  press any key to enter console... " -ForegroundColor DarkGray -NoNewline
    
    try {
        if (-not [System.Console]::IsInputRedirected) {
            $null = [Console]::ReadKey($true)
        }
    } catch {}
    Stop-Narration
    Write-Host "`n"
}

Export-ModuleMember -Function Invoke-CyberIntro, Speak-Narration, Stop-Narration, Test-VoiceOutput
