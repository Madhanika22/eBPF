
   This program will whitelist connections based on port.

   Explanation:
   - The program will filter incoming connections and allow only those connections that are made to specific ports listed in the whitelist.
   - Whitelisting connections based on port adds a layer of security by only permitting connections through approved ports, reducing the attack surface.
   - Ports not listed in the whitelist will be blocked, preventing unauthorized access attempts.

   Implementation details:
   - The program will maintain a list of whitelisted ports.
   - When a connection attempt is made, the program will check if the destination port is in the whitelist.
   - If the port is whitelisted, the connection will be accepted; otherwise, it will be rejected.


