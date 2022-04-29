# Polarity AbuseIPDB Integration

The Polarity - AbuseIPDB Integration supports enrichment of IP addresses in ipv4 and ipv6 format.

Check out the integration below:


| ![image](images/overlay.png) |![](images/overlay2.png)
|---|---|
|*100% Abuse Confidence* |*0% Abuse Confidence|

To learn more about AbuseIPDB, please visit: [official website](https://www.abuseipdb.com)

## AbuseIPDB Integration Options

### API Key
ApiKey needed to access the AbuseIPDB Api.

### Max Age in Days
Max age in days to search AbuseIPDB.  Defaults to 365.

> The max age must be in day format ranging from 1-365.

### Minimum Abuse Confidence Score
Minimum score you want to be notified of from AbuseIPDB.  Defaults to 0.

> The score value must be between 0 and 100.


### Baseline Investigation Threshold

Minimum Abuse Confidence Score for an IP to be (0-100) for an "investigation threshold met" icon to be displayed in the summary tag. Setting this value to -1 turns off the threshold. Defaults to 100.

## Installation Instructions

Installation instructions for integrations are provided on the [PolarityIO GitHub Page](https://polarityio.github.io/).

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
