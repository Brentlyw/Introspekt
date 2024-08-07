rule Detect_Stealers {
    meta:
        author = "Brentlyw"
        description = "Detect general information stealers"
        date = "2024-08-07"
        version = "1.0"

    strings:
        // Common strings found in stealers
        $browser_data = "AppData\\Local\\Google\\Chrome\\User Data"
        $firefox_data = "AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
        $discord_tokens = "discord_token"
        $steam_data = "Steam\\userdata"
        $wallets = "wallet.dat"
        $ftp_data = "FileZilla\\recentservers.xml"
        $passwords = "password"
        $cookies = "cookies"
        $user_agents = "User-Agent"
        $clipboard = "GetClipboardData"
        $screenshots = "screenshot"
        $keylog = "keylog"

    condition:
        2 of ($browser_data, $firefox_data, $discord_tokens, $steam_data, $wallets, $ftp_data, $passwords, $cookies, $user_agents, $clipboard, $screenshots, $keylog)
}
