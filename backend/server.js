const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const app = express();

app.use(cors({ origin: "*", methods: ["GET", "POST"], credentials: true }));
app.use(express.json());

const users = {};
const challenges = {};
const encryptedDataStore = {};

const rpID = "localhost";
const rpName = "My Simple WebAuth App";
const origin = "http://localhost:5173";

app.get("/register-options", async (req, res) => {
  const userId = req.query.userId || "phdang";
  const userIdBuffer = Buffer.from(userId);

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: userIdBuffer,
    userName: userId,
    attestationType: "none",
    authenticatorSelection: { userVerification: "preferred" },
  });

  challenges[userId] = options.challenge;
  res.json(options);
});

app.post("/register", async (req, res) => {
  const { userId, publicKey, ...body } = req.body;
  if (!userId || !publicKey)
    return res.status(400).json({ error: "userId and publicKey are required" });

  try {
    const verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge: challenges[userId],
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });

    if (verification.verified) {
      const { credential } = verification.registrationInfo;

      if (!credential || !credential.id || !credential.publicKey) {
        throw new Error("Missing credential data in registration info");
      }

      users[userId] = {
        credentialID: credential.id,
        publicKey: credential.publicKey,
        counter: verification.registrationInfo.counter,
        clientPublicKey: publicKey,
      };
      // pretend to store the sensitive data
      const sensitiveData = JSON.stringify({
        format: {
          size: "9607654",
          tags: {
            date: "2025",
            disc: "1/1",
            album:
              "DIGGIN' “GROOVE-DIGGERS” FEAT.WELDON IRVINE Unlimited Rare Groove Mixed By MURO",
            genre: "Jazz",
            title: "Mr.Clean",
            track: "5/15",
            artist: "Weldon Irvine",
            encoder: "ミュージック 1.0.6.10",
            iTunNORM:
              " 0000068A 000005B1 00008325 0000321B 00028EC8 00038FED 00008000 00008000 00018506 0000FDB2",
            iTunSMPB:
              " 00000000 00000840 000002EC 0000000000B110D4 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000",
            compilation: "0",
            major_brand: "M4A ",
            creation_time: "2025-02-21T10:36:43.000000Z",
            iTunes_CDDB_1:
              "D80DFE0F+268836+15+150+8418+32147+58960+75395+95130+126399+141060+156907+179056+197864+207776+215991+235338+247590",
            minor_version: "0",
            "Encoding Params": "vers",
            gapless_playback: "0",
            compatible_brands: "M4A mp42isom",
            iTunes_CDDB_TrackNumber: "5",
          },
          bit_rate: "292027",
          duration: "263.198186",
          filename: "05 Mr.Clean.m4a",
          mimetype: "audio/x-m4a",
          extension: "m4a",
          nb_streams: 1,
          start_time: "0.047891",
          format_name: "mov,mp4,m4a,3gp,3g2,mj2",
          nb_programs: 0,
          probe_score: 100,
          format_long_name: "QuickTime / MOV"
        },
      });

      const aesKey = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
      let encryptedData = cipher.update(sensitiveData, "utf8", "base64");
      encryptedData += cipher.final("base64");
      const authTag = cipher.getAuthTag();

      const masterKey = crypto.randomBytes(32);
      const masterIv = crypto.randomBytes(16);
      const masterCipher = crypto.createCipheriv(
        "aes-256-cbc",
        masterKey,
        masterIv
      );
      let encryptedAesKey = masterCipher.update(aesKey, "binary", "base64");
      encryptedAesKey += masterCipher.final("base64");

      const encryptedMasterKeys = {};
      encryptedMasterKeys[userId] = crypto
        .publicEncrypt(
          {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
          },
          masterKey
        )
        .toString("base64");
      const clonedKeys = { ...encryptedMasterKeys };
      (Object.keys(clonedKeys) || []).forEach((key) => {
        // remove other user's public key
        if (key !== userId) {
          delete clonedKeys[key];
        }
      });
      encryptedDataStore[userId] = {
        encryptedData,
        encryptedAesKey,
        iv: iv.toString("base64"),
        authTag: authTag.toString("base64"),
        masterIv: masterIv.toString("base64"),
        encryptedMasterKeys: clonedKeys,
        masterKey: masterKey.toString("base64"), // Secure this in production
      };

      delete challenges[userId];
      res.json({ success: true });
    } else {
      res.status(400).json({ success: false, error: "Verification failed" });
    }
  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/add-user-access", async (req, res) => {
  const { userId, newUserId, newPublicKey } = req.body;
  if (!userId || !newUserId || !newPublicKey) {
    return res
      .status(400)
      .json({ error: "userId, newUserId, and newPublicKey are required" });
  }

  const dataStore = encryptedDataStore[userId];
  if (!dataStore) {
    return res.status(404).json({ error: "Data for userId not found" });
  }

  try {
    const masterKey = Buffer.from(dataStore.masterKey, "base64");
    const encryptedMasterKey = crypto
      .publicEncrypt(
        {
          key: newPublicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        masterKey
      )
      .toString("base64");

    dataStore.encryptedMasterKeys[newUserId] = encryptedMasterKey;
    // remove other user's public key
    const clonedKeys = { ...dataStore.encryptedMasterKeys };
    Object.keys(clonedKeys).forEach((key) => {
      if (key !== newUserId) {
        delete clonedKeys[key];
      }
    });
    const updatedDataStore = { ...dataStore, encryptedMasterKeys: clonedKeys };
    res.json({ success: true, encryptedData: updatedDataStore });
  } catch (error) {
    console.error("Add User Access Error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/auth-options", async (req, res) => {
  const userId = req.query.userId || "phdang";
  const user = users[userId];

  if (!user) return res.status(404).json({ error: "User not found" });

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: [{ id: user.credentialID, type: "public-key" }],
    authenticatorSelection: { userVerification: "preferred" },
  });

  challenges[userId] = options.challenge;
  res.json(options);
});

app.post("/auth", async (req, res) => {
  const { userId, ...body } = req.body;
  if (!userId) return res.status(400).json({ error: "userId is required" });

  const user = users[userId];
  if (!user) return res.status(404).json({ error: "User not found" });

  try {
    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge: challenges[userId],
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: user.credentialID,
        publicKey: user.publicKey,
        counter: user.counter,
      },
      requireUserVerification: false,
    });

    if (verification.verified) {
      user.counter = verification.authenticationInfo.newCounter;
      delete challenges[userId];
      const dataStore = encryptedDataStore[userId];
      const { masterKey, ...clientData } = dataStore;
      // Secure this in production
      const clonedKeys = { ...dataStore.encryptedMasterKeys };
      Object.keys(clonedKeys).forEach((key) => {
        if (key !== userId) {
          delete clonedKeys[key];
        }
      });
      clientData.encryptedMasterKeys = clonedKeys;
      res.json({ success: true, encryptedData: clientData });
    } else {
      res.status(400).json({ success: false, error: "Authentication failed" });
    }
  } catch (error) {
    console.error("Auth Error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => console.log("Server running on port 3000"));
