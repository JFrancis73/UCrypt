<div align="center">

# U-CRYPT

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/JFrancis73/UCrypt/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Known Vulnerabilities](https://snyk.io/test/github/JFrancis73/UCrypt}/badge.svg)](https://snyk.io/test/github/JFrancis73/UCrypt)
</div>


# Installation

Getting started with UCrypt is a breeze! Choose your preferred installation method:

**Clone the repository:**

    git clone https://github.com/JFrancis73/UCrypt.git
    cd UCrypt/

**1. Assisted Installation (Recommended):**

If you're using a Debian-based Linux distribution (like Ubuntu or Kali) that uses the apt package manager, you can leverage the included setup script. The installer will handle all configurations and install the required dependencies.

Simply run the following command in your terminal:

    sudo python3 setup.py install

**2. Manual Installation:**

If you're not using a Debian-based distro or encounter issues with the setup script, you can still run UCrypt manually. Here's what you'll need to do:

*A. Modifying the Database Path (Optional):*

By default, UCrypt expects the database to be located at /var/lib/UCrypt/UCrypt.db. If you prefer a different location, you can modify the path directly within the ucrypt.py file. Edit line 15 to reflect your desired database path.

*B. Manual Database Setup:*

Alternatively, you can create the necessary directory structure and copy the database file:

Create the directory:

    sudo mkdir /var/lib/UCrypt/

Set appropriate permissions:

    sudo chmod 777 /var/lib/UCrypt/

Copy the database file:

    sudo cp UCrypt.db /var/lib/UCrypt/

Set permissions for the database file:

    sudo chmod 777 /var/lib/UCrypt/UCrypt.db

**Installing Python Libraries:**

UCrypt only relies on built-in Python libraries. However, to ensure their presence and update them if necessary, you can run:

    pip install -r requirements.txt

**Installing Linux Dependencies:**

Finally, install the required Linux dependencies using your package manager (apt in this example):

    sudo apt update
    sudo apt install ccrypt -y
    sudo apt install cryptsetup -y

Once you've completed these steps based on your preferred installation method, UCrypt should be ready to use!

# Usage

If you did the assisted install, you can use the tool simply by typing:

    ucrypt

If you did the manual install, you can run:

    python3 ucrypt.py
---
> [!NOTE]  
> You will have to run the tool as root if you intend to encrypt drives with it.
---

Once you launch it, just choose your preffered action and the intuitive GUI will prompt you for all the required information and the application will handle the rest.
Here are a few examples of what using the tool is like:


# Uninstalling UCrypt

If you no longer need UCrypt, you can uninstall it using the included setup.py:
	Just run the following command:
 
	sudo python setup.py uninstall
	
---
> [!WARNING]  
> If you uninstall the application, the data on files that are still encrypted by it will not be recoverable. Make sure you decrypt all your required files prior to uninstalling the application.
---

### Thank you for choosing UCrypt!

We hope this readme provides a clear guide to getting started with UCrypt. If you have any questions or encounter any issues, please don't hesitate to contact us.
