# Simple Web Auth App
Demonstrate web storing passphrase and use passphrase to authenticate

# Requirements
+ node version v20.14.0
+ NPM version 9.8.0

### Step 1 - Run Backend Server (on port 3000)
Open the terminal and run the following commands
``cd backend && npm install && npm run start``

### Step 2 - Run frontend ReactJs (on port 5173)
Open another terminal and run the following commands
``cd frontend && npm install && npm run dev``

### Step 3 - Using browser 1 to register and authenticate
Open the browser and visit http://localhost:5173
Click on register and create the passphrase, store the passphrase
in browser / iCloud or any devices depending on your preferences.
Click on authenticate button to authenticate to view the confidential / sensitive data
that only this user using this browser can see it.

### Step 4 - Using browser 2 to add another user (in practical operator / admin)
Open another browser or a new profile to visit the site:  http://localhost:5173
Click on the button "Add User B" to create the passphrase on another browser and 
this user B from this new browser to use this passphrase to see the confidential / sensitive information
of the user 1 (phdang) from step 3. You can change the name phdang as default from backend and frontend as your preferences.

### Step 5 - Refresh the page on browser 2 and click on Authenticate
From browser 2, the operator can refresh the page and click on "Authenticate" button to pretend
to sign in again and read the data of user 1 (phdang).

### Step 6 - Stop the server and website
Kill the terminal or use Ctrl + C to exit those two terminals in Step 1 and Step 2


