System Requirements

Akamai’s Splunk Connector requires Sun JDK 1.8+ to be installed. The latest JDK can be downloaded from the Sun Java site (Java Platform, Standard Edition) or installed from a software distribution package on Linux.

Hardware Requirements

This application is has been tested with the following Operating systems:
•	CentOS 7
•	Windows Server 2012 R2
•	Mac OS X El Capitan Version 10.11.6

Some additional hardware requirements as below:
•	4 CPU cores
•	16 GB RAM
•	2GB Free Disk Space

Installation Instructions

Download the latest TA-Akamai_SIEM_1_0_x.spl file(x being the latest version available). In Apps, click on "Install app from file" and add the .spl file. Click on upload - this may involve restarting Splunk instance to complete installation.

Once installation is complete, navigate to Settings -> Data Inputs and select the local input for "Security Information and Event Management". Here, configure all the customer-specific credentials, and click on Save. Once created, enable this stanza to start retrieval of data.

For more detailed installation instructions, please navigate here - https://developer.akamai.com/tools/siem-integration/docs/siem.htm (section Step 4 - Set up Splunk connector)
