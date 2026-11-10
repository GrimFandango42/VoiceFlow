# VF-18: render neutral test clips with the built-in Windows SAPI voices.
#
# There is no retained feedback audio on this machine (VOICEFLOW_FEEDBACK_AUDIO
# is opt-in), so the model comparison uses synthesized speech with a known
# reference text. That measures decode speed and word accuracy on clean speech;
# it does NOT measure accuracy on a real microphone, accents or room noise.
#
# Writes 16 kHz mono 16-bit WAVs plus reference.json to -OutDir.
#
# -Set mixed (default): the seven clips used for the item 5 model comparison.
# -Set short: eight 1-5 s utterances for the item 7 fast-path (tiny.en) check.
param(
    [Parameter(Mandatory = $true)][string]$OutDir,
    [ValidateSet("mixed", "short")][string]$Set = "mixed"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Speech
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$shortClips = @(
    @{ id = "s01"; text = "Yes, send it." },
    @{ id = "s02"; text = "Open the settings panel." },
    @{ id = "s03"; text = "Reply to Jennifer and say I will be late." },
    @{ id = "s04"; text = "Add milk and eggs to the shopping list." },
    @{ id = "s05"; text = "Run the unit tests again." },
    @{ id = "s06"; text = "Please schedule the quarterly review for next Tuesday afternoon." },
    @{ id = "s07"; text = "Commit the change and push it to the feature branch." },
    @{ id = "s08"; text = "What time is the meeting with the Madison team tomorrow?" }
)

$clips = @(
    @{ id = "short01"; text = "Please schedule the quarterly review for next Tuesday afternoon." },
    @{ id = "short02"; text = "Run the unit tests again and tell me which ones failed." },
    @{ id = "tech01"; text = "The Kubernetes deployment uses PostgreSQL with a Redis cache, and the pytest suite runs inside Docker on every pull request." },
    @{ id = "tech02"; text = "Set the compute type to float16 on the CUDA device and keep the beam size at one for the fastest decode." },
    @{ id = "mid01"; text = "I wanted to follow up on the document we discussed yesterday. The main change is that the approval step now happens before the review rather than after it, which should remove about two days from the schedule. Let me know if that works for everyone." },
    @{ id = "num01"; text = "The invoice total is one thousand two hundred and forty dollars, due on the fifteenth of March, and the purchase order number is four seven eight nine two." },
    @{ id = "long01"; text = "Here is a longer dictation to exercise the long form path. First, open the settings panel and confirm that the microphone is selected. Second, hold the hotkey, speak a full sentence, and release it. The transcription should appear in the active window within a second or so. If the text is missing, check the log file in the application data folder, and look for any line that mentions a fallback to the processor. Finally, restart the application and repeat the test twice to make sure the result is consistent every time." }
)

if ($Set -eq "short") { $clips = $shortClips }

$voices = @("Microsoft David Desktop", "Microsoft Zira Desktop")
$installed = (New-Object System.Speech.Synthesis.SpeechSynthesizer).GetInstalledVoices() | ForEach-Object { $_.VoiceInfo.Name }
$voices = @($voices | Where-Object { $installed -contains $_ })
if ($voices.Count -eq 0) { $voices = @($installed | Select-Object -First 1) }

$fmt = New-Object System.Speech.AudioFormat.SpeechAudioFormatInfo(16000, [System.Speech.AudioFormat.AudioBitsPerSample]::Sixteen, [System.Speech.AudioFormat.AudioChannel]::Mono)
$reference = [ordered]@{}
$i = 0
foreach ($clip in $clips) {
    $voice = $voices[$i % $voices.Count]
    $i++
    $name = "{0}.wav" -f $clip.id
    $synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
    $synth.SelectVoice($voice)
    $synth.SetOutputToWaveFile((Join-Path $OutDir $name), $fmt)
    $synth.Speak($clip.text)
    $synth.Dispose()
    $reference[$name] = [ordered]@{ voice = $voice; text = $clip.text }
}
$reference | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $OutDir "reference.json") -Encoding UTF8
Write-Host ("wrote {0} clips to {1} (voices: {2})" -f $clips.Count, $OutDir, ($voices -join ", "))
