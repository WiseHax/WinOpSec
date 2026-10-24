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
        [int]$MaxMs = 30000,
        [switch]$AllowSkip
    )

    $tts = Get-TtsVoiceEngine
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    Start-Sleep -Milliseconds 120

    while ($sw.ElapsedMilliseconds -lt $MaxMs) {
        if ($tts -and $tts.Type -eq "SAPI") {
            if ($tts.Engine.WaitUntilDone(150)) { break }
        } else {
            Start-Sleep -Milliseconds 150
        }

        if ($AllowSkip -and (Test-ConsoleKeyAvailable)) {
            $k = Read-ConsoleKeyIfAvailable
            if ($k) {
                if ($k.Key -eq [ConsoleKey]::Escape) {
                    Stop-Narration
                    return "SkipAll"
                } elseif ($k.Key -eq [ConsoleKey]::Spacebar -or $k.Key -eq [ConsoleKey]::Enter) {
                    Stop-Narration
                    return "SkipStep"
                }
            }
        }
    }

    Start-Sleep -Milliseconds 350
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
    Write-Host "  [press space or enter to skip step, esc to skip all]`n" -ForegroundColor DarkGray

    Play-SubtleTone -Freq 800 -DurationMs 60
    Play-SubtleTone -Freq 1100 -DurationMs 75

    if (-not $VoiceMute) {
        Speak-Narration -Text "Welcome to WinOpSec. Before you begin, here is what you need to know so you do not compromise your own security."
    }

    Write-AnimatedLine -Text "  > hello." -CharDelayMs $delay -Color Gray
    Start-Sleep -Milliseconds 120
    Write-AnimatedLine -Text "  > welcome to winopsec." -CharDelayMs $delay -Color Gray
    Start-Sleep -Milliseconds 120
    Write-AnimatedLine -Text "  > operator defensive briefing online." -CharDelayMs $delay -Color Green

    $null = Wait-NarrationFinish -MaxMs 30000 -AllowSkip

    Write-Host ""
    Play-SubtleTone -Freq 1300 -DurationMs 70

    Write-Host "  -- operational security rules: what NEVER to do ----------------" -ForegroundColor DarkGray

    $rules = @(
        @{
            Number  = "1"
            Title   = "PUBLIC WI-FI: Never surf on open networks with raw interfaces"
            Voice   = "Rule number one: Never use public Wi-Fi without locking your VPN and MAC address first. In a cafe or airport, anyone with an ARP-poisoning tool can intercept your session tokens. Always run Cafe Mode before you open a browser."
            Mistake = "Connecting unprotected to cafe, airport, or hotel Wi-Fi."
            Threat  = "Anyone on the LAN can run ARP poisoning, hijack DNS, or sniff session tokens."
            Fix     = "Run Cafe Mode to spoof your MAC, lock Mullvad killswitch, and arm Sentry."
            Command = "quick -> 1  or  sentry -autopanic"
        },
        @{
            Number  = "2"
            Title   = "CREDENTIALS & MEMORY: Never leave plaintext secrets on disk"
            Voice   = "Rule number two: Never leave plaintext credentials on your machine, and never leave LSASS memory unprotected. Basic infostealers dump LSASS memory in seconds. Host lockdown isolates LSASS in kernel memory so credentials cannot be dumped."
            Mistake = "Leaving .env files, private keys, or API tokens exposed on disk."
            Threat  = "Malware and infostealers harvest tokens and dump plaintext passwords from LSASS."
            Fix     = "Apply Host Lockdown to lock LSASS into kernel PPL and scan for exposed secrets."
            Command = "2  or  harden-all"
        },
        @{
            Number  = "3"
            Title   = "HARDWARE ATTACKS: Never plug in unknown flash drives"
            Voice   = "Rule number three: Never plug in untrusted USB drives or leave your ports unattended. BadUSB devices inject thousands of keystrokes the instant they connect. Keep Sentry active to alert on rogue USB devices, or arm DeadMan to panic if physical custody is lost."
            Mistake = "Plugging in a random flash drive or leaving laptop ports unguarded."
            Threat  = "BadUSB hardware registers as a keyboard and injects reverse shells in half a second."
            Fix     = "Arm Sentry to detect rogue USB devices, or use BusKill lanyard (DeadMan)."
            Command = "sentry  or  deadman"
        },
        @{
            Number  = "4"
            Title   = "FORENSIC ARTIFACTS: Never trust browser incognito mode alone"
            Voice   = "Rule number four: Never assume closing your browser makes you private. Incognito mode only clears temporary cookies. Windows secretly logs every application in PCA dictionaries and every folder in ShellBags. Always run wipe-pca and wipe-shellbags."
            Mistake = "Assuming private browsing leaves no traces on the computer."
            Threat  = "Windows 11 logs every executable run in PCA files and every folder browsed in ShellBags."
            Fix     = "Shred execution dictionaries and Explorer folder histories after your session."
            Command = "wipe-pca  and  wipe-shellbags  (or 6 / wipe)"
        },
        @{
            Number  = "5"
            Title   = "FORENSIC DECEPTION: Never leave a suspiciously empty machine"
            Voice   = "Rule number five: Don't make your computer look like a spy laptop. A completely wiped machine with zero recent files is a red flag to forensic investigators. Deploy civilian camouflage with Chameleon to blend into normal civilian noise."
            Mistake = "Zeroing every log and file, creating a totally blank machine."
            Threat  = "Forensics experts look for Evidence of Absence. A clean laptop screams you had something to hide."
            Fix     = "Deploy realistic civilian noise (recipes, notes, recent links) using Chameleon."
            Command = "chameleon"
        },
        @{
            Number  = "6"
            Title   = "AUTOMATION: Never guess commands when you are unsure"
            Voice   = "Rule number six: Don't guess commands under pressure. If you are ever unsure what to type, simply run quick. One click applies all the defensive measures for your current situation."
            Mistake = "Trying to remember dozens of complex terminal flags under stress."
            Threat  = "Configuration mistakes or forgotten flags that leave defensive gaps open."
            Fix     = "Use the 1-click Guided Scenario Wizard for instant, error-free defense profiles."
            Command = "quick"
        }
    )

    $interruptedAll = $false

    foreach ($r in $rules) {
        if ($interruptedAll) {
            Write-Host "`n  [$($r.Number)] $($r.Title)" -ForegroundColor White
            Write-Host "      blunder : " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($r.Mistake)" -ForegroundColor Gray
            Write-Host "      threat  : " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($r.Threat)" -ForegroundColor DarkGray
            Write-Host "      defense : " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($r.Fix)" -ForegroundColor Gray
            Write-Host "      command : " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($r.Command)" -ForegroundColor Green
            continue
        }

        if (-not $VoiceMute) {
            Speak-Narration -Text $r.Voice
        }

        Write-Host "`n  [$($r.Number)] $($r.Title)" -ForegroundColor White
        Write-Host "      blunder : " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($r.Mistake)" -ForegroundColor Gray
        Write-Host "      threat  : " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($r.Threat)" -ForegroundColor DarkGray
        Write-Host "      defense : " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($r.Fix)" -ForegroundColor Gray
        Write-Host "      command : " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($r.Command)" -ForegroundColor Green

        $skipState = Wait-NarrationFinish -MaxMs 30000 -AllowSkip
        if ($skipState -eq "SkipAll") {
            $interruptedAll = $true
            Stop-Narration
        }
    }

    if (-not $VoiceMute -and -not $interruptedAll) {
        Speak-Narration -Text "You are ready. Type quick to begin, or press enter to access the console."
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
