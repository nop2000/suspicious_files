rule Detect_Challenge_Command
{
    meta:
        description = "ตรวจจับคำว่า 'challenge' ในไฟล์หรือ payload"
        author = "คุณ"
        date = "2025-05-31"

    strings:
        $challenge_cmd = "challenge" nocase

    condition:
        $challenge_cmd
}
