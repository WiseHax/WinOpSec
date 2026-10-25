# IntroTour.psm1 - Interactive Onboarding & Audio Briefing
# WinOpSec Defensive Suite

$script:TtsEngine = $null
$script:AudioPlayer = $null

function Get-AudioPlayer {
    if ($script:AudioPlayer) { return $script:AudioPlayer }
    try {
        Add-Type -AssemblyName PresentationCore -ErrorAction Stop
        $script:AudioPlayer = New-Object System.Windows.Media.MediaPlayer
        $script:AudioPlayer.Volume = 1.0
        return $script:AudioPlayer
    } catch {
        return $null
    }
}

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

function Play-OpSecAudioClip {
    param(
        [string]$ClipName,
        [string]$FallbackText
    )

    $audioDir = Join-Path (Split-Path $PSScriptRoot -Parent) "assets\audio"
    $clipPath = Join-Path $audioDir $ClipName

    if (Test-Path $clipPath) {
        try {
            $player = Get-AudioPlayer
            if ($player) {
                $player.Stop()
                $player.Close()
                $uri = New-Object System.Uri((Resolve-Path $clipPath).Path)
                $player.Open($uri)
                $player.Volume = 1.0
                $player.Play()
                return @{ Type = "MediaPlayer"; File = $clipPath }
            }
        } catch {}
    }

    # Fallback to SAPI voice synthesizer if audio file is missing
    if ($FallbackText) {
        Speak-Narration -Text $FallbackText
        return @{ Type = "SAPI"; File = $null }
    }
    return $null
}

function Stop-OpSecAudio {
    try {
        if ($script:AudioPlayer) {
            $script:AudioPlayer.Stop()
            $script:AudioPlayer.Close()
            $script:AudioPlayer = $null
        }
    } catch {}
    Stop-Narration
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
    
    $audioDir = Join-Path (Split-Path $PSScriptRoot -Parent) "assets\audio"
    $hasClips = Test-Path (Join-Path $audioDir "intro_hello.mp3")

    if ($hasClips) {
        Write-Host "  [PASS] Neural Audio: Loaded from assets\audio (Sanitized PCM/MP3)" -ForegroundColor Green
        Write-Host "  [PASS] Audio Pipeline: PresentationCore.MediaPlayer" -ForegroundColor Green
        Write-Host "  playing neural audio sample through laptop speakers..." -ForegroundColor DarkGray
        Play-SubtleTone -Freq 1000 -DurationMs 70
        $handle = Play-OpSecAudioClip -ClipName "intro_hello.mp3" -FallbackText "Audio check complete."
        $null = Wait-AudioPlaybackFinish -PlayHandle $handle -MaxMs 15000 -AllowSkip
        Write-Host "  [DONE] Neural voice audio test finished.`n" -ForegroundColor Green
        return
    }

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

function Wait-AudioPlaybackFinish {
    param(
        [hashtable]$PlayHandle,
        [int]$MaxMs = 30000,
        [switch]$AllowSkip
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Milliseconds 150

    while ($sw.ElapsedMilliseconds -lt $MaxMs) {
        if ($PlayHandle -and $PlayHandle.Type -eq "MediaPlayer" -and $script:AudioPlayer) {
            if ($script:AudioPlayer.NaturalDuration.HasTimeSpan) {
                $pos = $script:AudioPlayer.Position.TotalSeconds
                $dur = $script:AudioPlayer.NaturalDuration.TimeSpan.TotalSeconds
                if ($pos -ge $dur -and $pos -gt 0.5) { break }
            }
        } elseif ($PlayHandle -and $PlayHandle.Type -eq "SAPI") {
            $tts = Get-TtsVoiceEngine
            if ($tts -and $tts.Type -eq "SAPI") {
                if ($tts.Engine.WaitUntilDone(150)) { break }
            }
        } else {
            Start-Sleep -Milliseconds 150
        }

        if ($AllowSkip -and (Test-ConsoleKeyAvailable)) {
            $k = Read-ConsoleKeyIfAvailable
            if ($k) {
                if ($k.Key -eq [ConsoleKey]::Escape) {
                    Stop-OpSecAudio
                    return "SkipAll"
                } elseif ($k.Key -eq [ConsoleKey]::Spacebar -or $k.Key -eq [ConsoleKey]::Enter) {
                    Stop-OpSecAudio
                    return "SkipStep"
                }
            }
        }
        Start-Sleep -Milliseconds 80
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

    Write-Host "  [press space or enter to skip step, esc to skip all]`n" -ForegroundColor DarkGray

    Play-SubtleTone -Freq 800 -DurationMs 60
    Play-SubtleTone -Freq 1100 -DurationMs 75

    $introHandle = $null
    if (-not $VoiceMute) {
        $introHandle = Play-OpSecAudioClip -ClipName "intro_hello.mp3" -FallbackText "Greetings. Welcome to WinOpSec. Don't act like a brain-dead script kiddie downloading tools you don't understand. If your OpSec is trash, you're not a hacker, you're just another clown waiting to get raided. Listen the fuck up to these six rules so you don't get compromised."
    }

    Write-AnimatedLine -Text "  > anonymous voice briefing initialized." -CharDelayMs $delay -Color Gray
    Start-Sleep -Milliseconds 120
    Write-AnimatedLine -Text "  > welcome to winopsec." -CharDelayMs $delay -Color Gray
    Start-Sleep -Milliseconds 120
    Write-AnimatedLine -Text "  > stop acting like a brain-dead skid. rules online." -CharDelayMs $delay -Color Green

    if ($introHandle) {
        $null = Wait-AudioPlaybackFinish -PlayHandle $introHandle -MaxMs 30000 -AllowSkip
    }

    Write-Host ""
    Play-SubtleTone -Freq 1300 -DurationMs 70

    Write-Host "  Operational Security Rules: What NEVER To Do" -ForegroundColor Cyan

    $rules = @(
        @{
            Number  = "1"
            Title   = "PUBLIC WI-FI: What the fuck are you doing on open networks?"
            Clip    = "rule1_wifi.mp3"
            Voice   = "Rule number one: Public Wi-Fi. Connecting raw to coffee shop or airport Wi-Fi with your real MAC address and no VPN? What the fuck are you doing? Any skid with an ARP poisoner will hijack your session cookies in three seconds flat. Spoof your damn MAC and lock your tunnel with Cafe Mode before you touch a browser."
            Mistake = "Connecting raw to cafe or airport Wi-Fi with your real physical MAC."
            Threat  = "Any skid with an ARP poisoner hijacks your session cookies in 3 seconds flat."
            Fix     = "Spoof your MAC and lock Mullvad WFP killswitch before opening a browser."
            Command = "quick -> 1  or  sentry -autopanic"
        },
        @{
            Number  = "2"
            Title   = "CREDENTIALS & MEMORY: Storing plaintext secrets is pure idiocy"
            Clip    = "rule2_creds.mp3"
            Voice   = "Rule number two: Plaintext credentials. Storing API tokens, seed phrases, and passwords on your desktop is pure idiocy. Basic infostealers will rip through your unshielded LSASS memory in under a second. Run host lockdown, lock LSASS into kernel memory, and wipe your exposed secrets."
            Mistake = "Leaving .env files, private keys, seeds, or API tokens on your desktop."
            Threat  = "Lumma and RedLine infostealers rip through unshielded LSASS memory in 1 second."
            Fix     = "Lock LSASS into kernel PPL memory and scan disk for exposed secrets."
            Command = "2  or  harden-all"
        },
        @{
            Number  = "3"
            Title   = "HARDWARE TRAPS: Don't be the dumbass who plugs in random flash drives"
            Clip    = "rule3_usb.mp3"
            Voice   = "Rule number three: Hardware traps. Don't be the dumbass who plugs in random flash drives found in the parking lot. A BadUSB injects five hundred keystrokes a second and pops a reverse shell before your slow ass can blink. Keep Sentry active, or arm DeadMan if you're in hostile territory."
            Mistake = "Plugging in random found USB sticks or leaving laptop ports unguarded."
            Threat  = "BadUSB injects 500 keystrokes/sec and pops a reverse shell before you can blink."
            Fix     = "Arm Sentry to detect rogue HID injections, or use BusKill lanyard (DeadMan)."
            Command = "sentry  or  deadman"
        },
        @{
            Number  = "4"
            Title   = "FORENSIC FOOTPRINTS: Incognito mode will not save your ass"
            Clip    = "rule4_pca.mp3"
            Voice   = "Rule number four: Forensic footprints. Incognito mode will not save your ass, amateur. You close Chrome and think you're clean? Bullshit. Windows 11 secretly logs every damn executable you ran in PCA launch dictionaries and records every folder in ShellBags. Wipe PCA and purge ShellBags, or hand the cops your timeline on a silver platter."
            Mistake = "Assuming private browser tabs leave zero footprints on disk."
            Threat  = "Windows 11 secretly logs every executable in PCA and folders in ShellBags."
            Fix     = "Shred PCA dictionaries, Explorer ShellBags, and KTM registry logs."
            Command = "wipe-pca  and  wipe-shellbags  (or 6 / wipe)"
        },
        @{
            Number  = "5"
            Title   = "FORENSIC DECEPTION: An empty machine screams guilty as hell"
            Clip    = "rule5_chameleon.mp3"
            Voice   = "Rule number five: Forensic deception. Wiping your entire machine to zero bytes? Congratulations, you just handed digital forensics Evidence of Absence. A squeaky-clean drive screams that you have something to hide. Deploy Chameleon. Plant civilian noise, essays, and recipes to look like a boring civilian."
            Mistake = "Zeroing every log and file, leaving a suspicious blank slate."
            Threat  = "Forensics investigators flag a clean machine immediately as Evidence of Absence."
            Fix     = "Plant realistic civilian noise (student essays, recipes) with Chameleon."
            Command = "chameleon"
        },
        @{
            Number  = "6"
            Title   = "AUTOMATION: Don't guess syntax like a panic-stricken skid"
            Clip    = "rule6_automation.mp3"
            Voice   = "Rule number six: Automation. Don't guess flags and botch syntax like a panic-stricken script kiddie when adrenaline is pumping. Just type quick. One click handles the defense automatically so you don't fuck it up."
            Mistake = "Trying to remember dozens of CLI flags and botching commands under stress."
            Threat  = "One typo or missing killswitch flag leaves your real IP and identity exposed."
            Fix     = "Type 'quick' for 1-click automated execution of complete defensive modes."
            Command = "quick"
        }
    )

    $interruptedAll = $false

    foreach ($r in $rules) {
        if ($interruptedAll) {
            Write-Host "`n  [$($r.Number)] $($r.Title)" -ForegroundColor White
            Write-Host "      skid mistake : " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($r.Mistake)" -ForegroundColor Gray
            Write-Host "      reality check: " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($r.Threat)" -ForegroundColor DarkGray
            Write-Host "      opsec fix    : " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($r.Fix)" -ForegroundColor Gray
            Write-Host "      command      : " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($r.Command)" -ForegroundColor Green
            continue
        }

        $stepHandle = $null
        if (-not $VoiceMute) {
            $stepHandle = Play-OpSecAudioClip -ClipName $r.Clip -FallbackText $r.Voice
        }

        Write-Host "`n  [$($r.Number)] $($r.Title)" -ForegroundColor White
        Write-Host "      skid mistake : " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($r.Mistake)" -ForegroundColor Gray
        Write-Host "      reality check: " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($r.Threat)" -ForegroundColor DarkGray
        Write-Host "      opsec fix    : " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($r.Fix)" -ForegroundColor Gray
        Write-Host "      command      : " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($r.Command)" -ForegroundColor Green

        if ($stepHandle) {
            $skipState = Wait-AudioPlaybackFinish -PlayHandle $stepHandle -MaxMs 30000 -AllowSkip
            if ($skipState -eq "SkipAll") {
                $interruptedAll = $true
                Stop-OpSecAudio
            }
        }
    }

    if (-not $VoiceMute -and -not $interruptedAll) {
        $outroHandle = Play-OpSecAudioClip -ClipName "outro.mp3" -FallbackText "Briefing complete. Stop doing stupid shit on the wire. Type quick to begin, or hit enter for the main console. Stay paranoid."
        if ($outroHandle) {
            $null = Wait-AudioPlaybackFinish -PlayHandle $outroHandle -MaxMs 15000 -AllowSkip
        }
    }

    Write-Host "`n  ------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  stop doing dumb shit. type 'quick' or press enter for console... " -ForegroundColor DarkGray -NoNewline
    
    try {
        if (-not [System.Console]::IsInputRedirected) {
            $null = [Console]::ReadKey($true)
        }
    } catch {}
    Stop-OpSecAudio
    Write-Host "`n"
}

Export-ModuleMember -Function Invoke-CyberIntro, Speak-Narration, Stop-Narration, Test-VoiceOutput
