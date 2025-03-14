## We own the domain now what?  
In the event we manage to compromise Domain and there is still time in the engagement, we will continue to provide as much value to the client as possible.  

1. Dump NTDS.dit and crack passwords.
2. Enumerate further shares for sensitive information such as PII data and other findings so that this can be reported.
3. Create persistence in the event our main access is lost and also remember to remove rouge Domain Admin accounts.
4. Test for detections espicially for DA account creations. A good environment should detect these account creations.
5. Creating a Golden Ticket.

---

## 🚩 Dumping the NTDS.dit

### What is NTDS.dit?  
An extremely critical and highly sensitive database used to store AD data:
* user information
* gorup information
* security dscriptors
* password hashes
