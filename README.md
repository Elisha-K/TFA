# Overview
This project designs and implements an Automated Cyber Threat Intelligence Feed Aggregator that
collects, parses, and forwards Indicators of Compromise (IOCs) from multiple threat intelligence
sources into a centralized SIEM platform; in this case, Wazuh. 

The system is thus used to speed up the process of obtaining relevant threat intelligence and integrating it with SIEM toolkits for faster
correlation with logs and enhanced threat event detection.

# Background
Threats and threat-actors are becoming increasingly advanced and much more sophisticated. 
Complicated Tactics, Techniques and Procedures (TTPs) are being witnessed at an alarming rate.

These TTPs are geared towards enhancing detection-evasion capabilities, establishing persistence and improving outcomes on actions-on-objectives. 
Security Operations Centres (SOCs) are now under more pressure to stay ahead of the curve. 

To therefore keep up with these emerging trends, defense teams and security organizations globally seek to make information on observed TTPs, 
Indicators of Compromise (IOCs) and other such metrics open-source and publicly available. 

This information, published on sites such as AlienVault, MISP, IBM X-Force, constitutes *Cyber Threat
Intelligence.*

However, the body of information on this is so large and disparate that it poses a
challenge for in-house cyberdefense teams in the collection, integration and correlation with in-
house cyberdefense tools such as Security Information and Event Management (SIEM) tools. 

Thus, a tool that could automate this process would be extremely useful in enhancing threat detection capabilities, especially within small to midsize organisations
that often lack these capabilities.
