# tenhou-secure

The tenhou Windows client looks awesome. However, the traffic between the
client and tenhou server is NOT encrypted, including your unique secret player ID.

To fix this, simply run `python3 main.py` before you start the Windows client.
A proxy pretending to be a tenhou web client will initiate a secure WSS connection
to the tenhou server. 

