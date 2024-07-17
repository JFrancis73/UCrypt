import subprocess

user = subprocess.run(["whoami"],stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)				#Check if the script is run as root
if user.stdout.strip() != "root":
	print("Please Run the setup as root")
	exit()

import sys
import os

def Install():				#Install Dependencies
	import sqlite3
	print("[+] Installing U-Crypt...")
	
	result = subprocess.run(["apt","install","python3-pip","-y"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)			#Install pip
	if result.returncode != 0:
		print("[-] Error", "Failed to Initialize pip")
		return False
	
	user = subprocess.run(["who","am","i"],stdout=subprocess.PIPE,text=True)														#Get actual username of the user (not root) to install python libraries
	user = user.stdout.split()[0].strip()
	
	result = subprocess.run(["sudo","-u",user,"pip","install","-r","requirements.txt"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)		#Install/Update python libraries (not as root)
	#print(result.stdout)
	#print(result.stderr)
	if result.returncode != 0:
		print("[-] Error", "Failed to install required python libraries")
		return False
	result = subprocess.run(["pip","install","-r","requirements.txt"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)		#Install/Update python libraries for root as well just in case
	if result.returncode != 0:
		print("[-] Error", "Failed to install required python libraries")
		return False
	else:
		print("[+] Python libraries installed")
			
	if not os.path.isfile("/var/lib/UCrypt/UCrypt.db"):																#Create database if it doesn't exist
		if not os.path.exists("/var/lib/UCrypt/"):
			result = subprocess.run(["mkdir","/var/lib/UCrypt/"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)
			if result.returncode != 0:
				print("[-] Error", "Failed to create database")
				return False
			else:
				print("[+] Directory Initialized")
			
		result = subprocess.run(["touch","/var/lib/UCrypt/UCrypt.db"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)
		if result.returncode != 0:
			print("[-] Error", "Failed to create database")
			return False
		else:
			print("[+] Encryption Database Created")
			
		result = subprocess.run(["chmod","777", "/var/lib/UCrypt/"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)            #Change permissions
		if result.returncode != 0:
			print("[-] Error", "Failed to grant permissions")
			return False
		result = subprocess.run(["chmod","777", "/var/lib/UCrypt/UCrypt.db"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)
		if result.returncode != 0:
			print("[-] Error", "Failed to grant permissions")
			return False
		else:
			print("[+] Permissions Granted")
			
	conn = sqlite3.connect("/var/lib/UCrypt/UCrypt.db")																																				#Create Encryption Table in database
	conn.execute("CREATE TABLE IF NOT EXISTS Auth_Table(UID VARCHAR(32) PRIMARY KEY, FileName VARCHAR(100), Password VARCHAR(128))")
	
	result = subprocess.run(["apt","update"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)																		#Run apt-update and install linux dependancies
	if result.returncode != 0:
		print("[-] Error", "Failed to apt update")
	
	result = subprocess.run(["apt","install","ccrypt","-y"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)
	if result.returncode != 0:
		print("[-] Error", "Failed to initialize ccrypt")
		return False
	else:
		print("[+] Initialized ccrypt")

	result = subprocess.run(["apt","install","cryptsetup","-y"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)
	if result.returncode != 0:
		print("[-] Error", "Failed to initialize cryptsetup")
		return False
	else:
		print("[+] Initialized cryptsetup")
		
	#result = subprocess.run(["find", "/home/","-name", "ucrypt.py"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)
	#if result.returncode != 0:
		#print("[-] Error", "Could not find script ")
		#return False
		
	#path = result.stdout.strip()
	result = subprocess.run(["chmod","775","./ucrypt.py"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)							#Make the python script executable
	if result.returncode != 0:
		print("[-] Error", "Failed to Create Executable")
		return False
	else:
		print("[+] Created Executable")
		
	result = subprocess.run(["cp","./ucrypt.py","/usr/local/src/"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)		#Transfer source code to avoid errors due to altering file structure
	if result.returncode != 0:
		print("[-] Error", "Failed to transfer source.")
		return False
		
	result = subprocess.run(["ln","-s","/usr/local/src/ucrypt.py","/usr/local/bin/ucrypt"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)     #create symlink 
	if result.returncode != 0:
		print("[-] Error", "Failed to set up Symlink")
		return False
	else:
		print("[+] Set up Symlink")
		
	return True	

def Uninstall():															#Uninstall/ Undo the changes made by the Install Function
	print("[+] Uninstalling UCrypt")
	if os.path.isfile("/var/lib/UCrypt/UCrypt.db"):																																							#Remove database if it exists
		result = subprocess.run(["rm","-rf","/var/lib/UCrypt/"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)
		if result.returncode != 0:
			print("[-] Error", "Failed to delete database")
			return False
		else:
			print("[+] Removed Encryption Database.")

	if os.path.isfile("/usr/local/src/ucrypt.py"):
		result = subprocess.run(["rm","/usr/local/src/ucrypt.py"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)
		if result.returncode != 0:
			print("[-] Error", "Failed to remove source code.")																																									#Remove copied if it exists
			return False
		
	result = subprocess.run(["whereis","ucrypt"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)
	if len(result.stdout.split()) > 1:
		result = subprocess.run(["rm","/usr/local/bin/ucrypt"],stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)								#Remove Symlink if it exists
		if result.returncode != 0:
			print("[-] Error", "Failed to remove Symlink")
			return False
		else:
			print("[+] Removed Symlink")
		
	return True


if len(sys.argv) < 2 or sys.argv[1] == "install":
	if Install():
		print("[+] U-Crypt Installed Succesfully!\nUse the command \"ucrypt\" to start using it.")
	else:
		print("[-] Installation Aborted!")

elif sys.argv[1] == "uninstall":
	confirmation = input("Warning! All Data in Files That Are Still Encrypted Will be Unrecoverable\n Do you Wish to Continue? (y/N): ")
	if confirmation.lower() == 'y':
		if Uninstall():
			print("[+] U-Crypt Uninstalled Successfully!")
		else:
			print("[-] Could not Uninstall the application!")
	else:
		print("[-] Uninstall Aborted!")
else:
	print("Invalid option: Kindly read the documentaion: linktogithub")
